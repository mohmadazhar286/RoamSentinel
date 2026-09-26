using RoamSentinel.Config;
using RoamSentinel.Core;
using RoamSentinel.Database;
using RoamSentinel.Database.Migrations;
using RoamSentinel.Logs;
using RoamSentinel.MobileBridge;

namespace RoamSentinel.Tests;

public sealed class MobileBridgeTests : IDisposable
{
    private readonly string _testRoot = Path.Combine(
        Path.GetTempPath(),
        "RoamSentinel.MobileBridge.Tests",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public void MobileBridge_EnrollsDeviceAndStoresTelemetry()
    {
        var factory = CreateMigratedFactory();
        var repository = new MobileDeviceRepository(factory);
        var service = new MobileBridgeService(
            repository,
            NullStructuredLogService.Instance);

        var pairing = service.CreatePairingSession("Administrator");
        Assert.False(string.IsNullOrWhiteSpace(pairing.PairingCode));

        var enrollment = service.Enroll(new MobileEnrollmentRequest(
            pairing.PairingCode,
            "android-test-1",
            "Pixel Test",
            "Android",
            "Google",
            "Pixel",
            "15",
            "0.1.0"));

        Assert.True(enrollment.Ok);
        Assert.False(string.IsNullOrWhiteSpace(enrollment.DeviceToken));

        var heartbeat = service.RecordHeartbeat(new MobileHeartbeatRequest(
            enrollment.DeviceToken,
            enrollment.DeviceId,
            83,
            false,
            64_000,
            true,
            true,
            true,
            true,
            false,
            DateTimeOffset.UtcNow));

        Assert.True(heartbeat.RiskScore >= 70);
        Assert.Contains("USB debugging", heartbeat.RiskReason);

        service.RecordAppInventory(new MobileAppInventoryRequest(
            enrollment.DeviceToken,
            enrollment.DeviceId,
            DateTimeOffset.UtcNow,
            [
                new MobileAppInventoryItemDto(
                    "org.example.sideload",
                    "Sideloaded Test",
                    "1.0",
                    1,
                    "",
                    false,
                    true,
                    ["android.permission.READ_SMS"],
                    DateTimeOffset.UtcNow.AddDays(-2),
                    DateTimeOffset.UtcNow.AddDays(-1),
                    "")
            ]));

        service.RecordFindings(new MobileFindingsRequest(
            enrollment.DeviceToken,
            enrollment.DeviceId,
            DateTimeOffset.UtcNow,
            [
                new MobileSecurityFindingDto(
                    "finding-1",
                    DateTimeOffset.UtcNow,
                    "high",
                    80,
                    "mobile-posture",
                    "Sideloaded app detected",
                    "The companion reported an app installed outside the trusted store.",
                    "package",
                    "org.example.sideload",
                    "open")
            ]));

        var dashboard = service.GetDashboard();
        Assert.Contains(dashboard.Devices, device => device.DeviceId == enrollment.DeviceId);
        Assert.Contains(dashboard.RecentApps, app => app.PackageName == "org.example.sideload");
        Assert.Contains(dashboard.Findings, finding => finding.FindingId == "finding-1");
        Assert.True(dashboard.Policy.AlertOnSideloadedApps);

        var audit = new AuditRepository(factory).GetRecent(20);
        Assert.Contains(audit, entry => entry.Action == "mobile.device.enrolled");
        Assert.Contains(audit, entry => entry.Action == "mobile.inventory.recorded");
        Assert.Contains(audit, entry => entry.Action == "mobile.findings.recorded");
    }

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        if (Directory.Exists(_testRoot))
        {
            Directory.Delete(_testRoot, recursive: true);
        }
    }

    private SqliteConnectionFactory CreateMigratedFactory()
    {
        var factory = new SqliteConnectionFactory(
            _testRoot,
            new DatabaseOptions
            {
                FilePath = "test.db"
            });
        new DatabaseMigrationRunner(
            factory,
            [
                new InitialSchemaMigration(),
                new NormalizedTelemetryMigration(),
                new UnifiedDetectionMigration(),
                new LegacyDetectionMappingCleanupMigration(),
                new MitreCoverageMigration(),
                new ThreatIntelligenceMigration(),
                new ResponseControlMigration(),
                new AgentGovernanceMigration(),
                new AgentCatalogSafetyMigration(),
                new DeviceIntegrityMigration(),
                new MobileBridgeMigration()
            ]).Migrate();
        return factory;
    }
}