using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RoamSentinel.Core;

namespace RoamSentinel.MobileBridge;

public sealed class MobileBridgeService(
    IMobileDeviceRepository repository,
    IStructuredLogService logs) : IMobileBridgeService
{
    private static readonly TimeSpan PairingLifetime = TimeSpan.FromMinutes(10);

    public MobileDashboardViewDto GetDashboard() => repository.GetDashboard();

    public MobilePairingSessionDto CreatePairingSession(string actor)
    {
        var code = CreatePairingCode();
        var session = repository.CreatePairingSession(
            HashSecret(code),
            DateTimeOffset.UtcNow.Add(PairingLifetime),
            actor);
        logs.Security(
            "mobile.pairing.created",
            "Mobile pairing code created.",
            new { session.PairingId, session.ExpiresAt, Actor = actor });
        return session with { PairingCode = code };
    }

    public MobileEnrollmentResultDto Enroll(MobileEnrollmentRequest request)
    {
        ValidateEnrollment(request);
        var session = repository.FindActivePairingSession(
            HashSecret(request.PairingCode),
            DateTimeOffset.UtcNow);
        if (session is null)
        {
            logs.Security(
                "mobile.enrollment.denied",
                "Mobile enrollment rejected because the pairing code was invalid or expired.",
                new { request.DeviceId, request.Platform });
            return new(false, request.DeviceId, "", "Invalid or expired pairing code.");
        }

        var token = CreateDeviceToken();
        var device = repository.UpsertDevice(
            new MobileDeviceRegistration(
                NormalizeIdentifier(request.DeviceId),
                Clean(request.DisplayName, 120),
                Clean(request.Platform, 40),
                Clean(request.Manufacturer, 80),
                Clean(request.Model, 80),
                Clean(request.OsVersion, 80),
                Clean(request.AppVersion, 40),
                HashSecret(token)),
            "mobile-pairing");
        repository.MarkPairingSessionUsed(session.PairingId, device.DeviceId);
        logs.Security(
            "mobile.device.enrolled",
            "Mobile device enrolled.",
            new { device.DeviceId, device.Platform, device.DisplayName });
        return new(true, device.DeviceId, token, "Device enrolled.");
    }

    public MobileDeviceDto RecordHeartbeat(MobileHeartbeatRequest request)
    {
        ValidateDeviceRequest(request.DeviceId, request.DeviceToken);
        var device = repository.FindDeviceByTokenHash(HashSecret(request.DeviceToken))
            ?? throw new UnauthorizedAccessException("Invalid mobile device token.");
        if (!string.Equals(device.DeviceId, NormalizeIdentifier(request.DeviceId), StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException("Mobile device token does not match the device id.");
        }

        var updated = repository.RecordHeartbeat(HashSecret(request.DeviceToken), request);
        logs.App(
            "mobile.heartbeat.recorded",
            "Mobile heartbeat recorded.",
            new { updated.DeviceId, updated.RiskScore, updated.RiskReason });
        return updated;
    }

    public void RecordAppInventory(MobileAppInventoryRequest request)
    {
        ValidateDeviceRequest(request.DeviceId, request.DeviceToken);
        if (request.Apps.Count > 2000)
        {
            throw new ArgumentException("App inventory is too large.");
        }

        var device = AuthorizedDevice(request.DeviceId, request.DeviceToken);
        repository.ReplaceAppInventory(
            device.DeviceId,
            request.Apps.Select(NormalizeApp).ToList(),
            request.ObservedAt == default ? DateTimeOffset.UtcNow : request.ObservedAt);
        logs.App(
            "mobile.inventory.recorded",
            "Mobile app inventory recorded.",
            new { device.DeviceId, Apps = request.Apps.Count });
    }

    public void RecordFindings(MobileFindingsRequest request)
    {
        ValidateDeviceRequest(request.DeviceId, request.DeviceToken);
        if (request.Findings.Count > 500)
        {
            throw new ArgumentException("Finding batch is too large.");
        }

        var device = AuthorizedDevice(request.DeviceId, request.DeviceToken);
        repository.AddFindings(
            device.DeviceId,
            request.Findings.Select(NormalizeFinding).ToList(),
            request.ObservedAt == default ? DateTimeOffset.UtcNow : request.ObservedAt);
        logs.Security(
            "mobile.findings.recorded",
            "Mobile security findings recorded.",
            new { device.DeviceId, Findings = request.Findings.Count });
    }

    private MobileDeviceDto AuthorizedDevice(string deviceId, string token)
    {
        var device = repository.FindDeviceByTokenHash(HashSecret(token))
            ?? throw new UnauthorizedAccessException("Invalid mobile device token.");
        if (!string.Equals(device.DeviceId, NormalizeIdentifier(deviceId), StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException("Mobile device token does not match the device id.");
        }

        return device;
    }

    private static MobileAppInventoryItemDto NormalizeApp(MobileAppInventoryItemDto app)
    {
        if (string.IsNullOrWhiteSpace(app.PackageName) || app.PackageName.Length > 240)
        {
            throw new ArgumentException("Invalid app package name.");
        }

        return app with
        {
            PackageName = Clean(app.PackageName, 240),
            AppName = Clean(app.AppName, 160),
            VersionName = Clean(app.VersionName, 80),
            InstallerPackage = Clean(app.InstallerPackage, 160),
            RequestedPermissions = app.RequestedPermissions
                .Where(permission => !string.IsNullOrWhiteSpace(permission))
                .Take(200)
                .Select(permission => Clean(permission, 180))
                .ToList(),
            Sha256 = Clean(app.Sha256, 128)
        };
    }

    private static MobileSecurityFindingDto NormalizeFinding(MobileSecurityFindingDto finding)
    {
        var severity = Clean(finding.Severity, 20).ToLowerInvariant();
        if (severity is not ("info" or "low" or "medium" or "high" or "critical"))
        {
            severity = "info";
        }

        return finding with
        {
            FindingId = string.IsNullOrWhiteSpace(finding.FindingId)
                ? Guid.NewGuid().ToString("N")
                : Clean(finding.FindingId, 128),
            ObservedAt = finding.ObservedAt == default ? DateTimeOffset.UtcNow : finding.ObservedAt,
            Severity = severity,
            RiskScore = Math.Clamp(finding.RiskScore, 0, 100),
            Category = Clean(finding.Category, 80),
            Title = Clean(finding.Title, 160),
            Detail = Clean(finding.Detail, 1000),
            EntityType = Clean(finding.EntityType, 80),
            EntityId = Clean(finding.EntityId, 240),
            Status = string.IsNullOrWhiteSpace(finding.Status) ? "open" : Clean(finding.Status, 40)
        };
    }

    private static void ValidateEnrollment(MobileEnrollmentRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.PairingCode) || request.PairingCode.Length > 32)
        {
            throw new ArgumentException("Invalid pairing code.");
        }

        if (string.IsNullOrWhiteSpace(request.DeviceId) || request.DeviceId.Length > 128)
        {
            throw new ArgumentException("Invalid device id.");
        }
    }

    private static void ValidateDeviceRequest(string deviceId, string token)
    {
        if (string.IsNullOrWhiteSpace(deviceId) || deviceId.Length > 128)
        {
            throw new ArgumentException("Invalid device id.");
        }

        if (string.IsNullOrWhiteSpace(token) || token.Length > 256)
        {
            throw new UnauthorizedAccessException("Invalid mobile device token.");
        }
    }

    private static string CreatePairingCode()
    {
        Span<byte> bytes = stackalloc byte[4];
        RandomNumberGenerator.Fill(bytes);
        var number = BitConverter.ToUInt32(bytes) % 1_000_000;
        return number.ToString("D6");
    }

    private static string CreateDeviceToken()
    {
        Span<byte> bytes = stackalloc byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes);
    }

    private static string HashSecret(string secret) => Convert.ToHexString(
        SHA256.HashData(Encoding.UTF8.GetBytes(secret.Trim())));

    private static string NormalizeIdentifier(string value) => Clean(value, 128);

    private static string Clean(string? value, int maxLength)
    {
        var clean = (value ?? string.Empty).Replace("\0", string.Empty).Trim();
        return clean.Length <= maxLength ? clean : clean[..maxLength];
    }
}