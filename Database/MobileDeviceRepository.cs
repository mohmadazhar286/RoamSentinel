using System.Text.Json;
using Microsoft.Data.Sqlite;
using RoamSentinel.Core;

namespace RoamSentinel.Database;

public sealed class MobileDeviceRepository(
    IDatabaseConnectionFactory connections) : IMobileDeviceRepository
{
    public MobileDashboardViewDto GetDashboard()
    {
        using var connection = connections.OpenConnection();
        return new MobileDashboardViewDto(
            DateTimeOffset.UtcNow,
            ReadDevices(connection, 100),
            ReadRecentApps(connection, 200),
            ReadFindings(connection, 200),
            ReadNetworkEvents(connection, 200),
            ReadPolicy(connection));
    }

    public MobilePairingSessionDto CreatePairingSession(
        string codeHash,
        DateTimeOffset expiresAt,
        string actor)
    {
        var session = new MobilePairingSessionDto(
            Guid.NewGuid().ToString("N"),
            string.Empty,
            DateTimeOffset.UtcNow,
            expiresAt,
            "active");
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        using (var expire = connection.CreateCommand())
        {
            expire.Transaction = transaction;
            expire.CommandText = """
                UPDATE mobile_pairing_sessions
                SET status='expired'
                WHERE status='active' AND expires_at < $now;
                """;
            expire.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
            expire.ExecuteNonQuery();
        }

        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO mobile_pairing_sessions(
                    pairing_id, code_hash, created_at, expires_at, status,
                    created_by, used_by_device_id, used_at)
                VALUES($id,$hash,$created,$expires,'active',$actor,NULL,NULL);
                """;
            command.Parameters.AddWithValue("$id", session.PairingId);
            command.Parameters.AddWithValue("$hash", codeHash);
            command.Parameters.AddWithValue("$created", session.CreatedAt.ToString("O"));
            command.Parameters.AddWithValue("$expires", session.ExpiresAt.ToString("O"));
            command.Parameters.AddWithValue("$actor", actor);
            command.ExecuteNonQuery();
        }

        AuditSql.Insert(
            connection,
            transaction,
            actor,
            "mobile.pairing.created",
            "mobile_pairing_session",
            session.PairingId,
            true,
            JsonSerializer.Serialize(new { session.ExpiresAt }));
        transaction.Commit();
        return session;
    }

    public MobilePairingSessionDto? FindActivePairingSession(
        string codeHash,
        DateTimeOffset now)
    {
        using var connection = connections.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT pairing_id, created_at, expires_at, status
            FROM mobile_pairing_sessions
            WHERE code_hash=$hash AND status='active' AND expires_at >= $now
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("$hash", codeHash);
        command.Parameters.AddWithValue("$now", now.ToString("O"));
        using var reader = command.ExecuteReader();
        return reader.Read()
            ? new MobilePairingSessionDto(
                reader.GetString(0),
                string.Empty,
                DateTimeOffset.Parse(reader.GetString(1)),
                DateTimeOffset.Parse(reader.GetString(2)),
                reader.GetString(3))
            : null;
    }

    public void MarkPairingSessionUsed(string pairingId, string deviceId)
    {
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE mobile_pairing_sessions
            SET status='used', used_by_device_id=$deviceId, used_at=$usedAt
            WHERE pairing_id=$pairingId AND status='active';
            """;
        command.Parameters.AddWithValue("$deviceId", deviceId);
        command.Parameters.AddWithValue("$usedAt", DateTimeOffset.UtcNow.ToString("O"));
        command.Parameters.AddWithValue("$pairingId", pairingId);
        command.ExecuteNonQuery();
        AuditSql.Insert(
            connection,
            transaction,
            "mobile-pairing",
            "mobile.pairing.used",
            "mobile_device",
            deviceId,
            true,
            JsonSerializer.Serialize(new { PairingId = pairingId }));
        transaction.Commit();
    }

    public MobileDeviceDto UpsertDevice(
        MobileDeviceRegistration registration,
        string actor)
    {
        var now = DateTimeOffset.UtcNow;
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO mobile_devices(
                device_id, display_name, platform, manufacturer, model,
                os_version, app_version, status, token_hash, first_seen_at,
                last_seen_at, last_heartbeat_at, risk_score, risk_reason)
            VALUES($id,$name,$platform,$manufacturer,$model,$os,$app,'unknown',
                $token,$now,$now,NULL,0,'Newly enrolled device.')
            ON CONFLICT(device_id) DO UPDATE SET
                display_name=excluded.display_name,
                platform=excluded.platform,
                manufacturer=excluded.manufacturer,
                model=excluded.model,
                os_version=excluded.os_version,
                app_version=excluded.app_version,
                token_hash=excluded.token_hash,
                last_seen_at=excluded.last_seen_at;
            """;
        command.Parameters.AddWithValue("$id", registration.DeviceId);
        command.Parameters.AddWithValue("$name", registration.DisplayName);
        command.Parameters.AddWithValue("$platform", registration.Platform);
        command.Parameters.AddWithValue("$manufacturer", registration.Manufacturer);
        command.Parameters.AddWithValue("$model", registration.Model);
        command.Parameters.AddWithValue("$os", registration.OsVersion);
        command.Parameters.AddWithValue("$app", registration.AppVersion);
        command.Parameters.AddWithValue("$token", registration.TokenHash);
        command.Parameters.AddWithValue("$now", now.ToString("O"));
        command.ExecuteNonQuery();
        AuditSql.Insert(
            connection,
            transaction,
            actor,
            "mobile.device.enrolled",
            "mobile_device",
            registration.DeviceId,
            true,
            JsonSerializer.Serialize(new
            {
                registration.DisplayName,
                registration.Platform,
                registration.Manufacturer,
                registration.Model,
                registration.OsVersion,
                registration.AppVersion
            }));
        transaction.Commit();
        return ReadDeviceById(connection, registration.DeviceId)!;
    }

    public MobileDeviceDto? FindDeviceByTokenHash(string tokenHash)
    {
        using var connection = connections.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT device_id, display_name, platform, manufacturer, model,
                   os_version, app_version, status, first_seen_at,
                   last_seen_at, last_heartbeat_at, risk_score, risk_reason
            FROM mobile_devices
            WHERE token_hash=$token;
            """;
        command.Parameters.AddWithValue("$token", tokenHash);
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadDevice(reader) : null;
    }

    public MobileDeviceDto RecordHeartbeat(
        string tokenHash,
        MobileHeartbeatRequest request)
    {
        var risk = ScoreHeartbeat(request);
        var now = DateTimeOffset.UtcNow;
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE mobile_devices
            SET last_seen_at=$now,
                last_heartbeat_at=$observed,
                risk_score=$risk,
                risk_reason=$reason
            WHERE token_hash=$token;
            """;
        command.Parameters.AddWithValue("$now", now.ToString("O"));
        command.Parameters.AddWithValue("$observed", SafeTime(request.ObservedAt).ToString("O"));
        command.Parameters.AddWithValue("$risk", risk.Score);
        command.Parameters.AddWithValue("$reason", risk.Reason);
        command.Parameters.AddWithValue("$token", tokenHash);
        command.ExecuteNonQuery();
        AuditSql.Insert(
            connection,
            transaction,
            "mobile-device",
            "mobile.heartbeat.recorded",
            "mobile_device",
            request.DeviceId,
            true,
            JsonSerializer.Serialize(new
            {
                request.BatteryPercent,
                request.ScreenLockEnabled,
                request.DeveloperModeEnabled,
                request.UsbDebuggingEnabled,
                request.UnknownSourcesEnabled,
                request.VpnActive,
                risk.Score,
                risk.Reason
            }));
        transaction.Commit();
        return ReadDeviceById(connection, request.DeviceId)!;
    }

    public void ReplaceAppInventory(
        string deviceId,
        IReadOnlyCollection<MobileAppInventoryItemDto> apps,
        DateTimeOffset observedAt)
    {
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        using (var delete = connection.CreateCommand())
        {
            delete.Transaction = transaction;
            delete.CommandText = "DELETE FROM mobile_app_inventory WHERE device_id=$device;";
            delete.Parameters.AddWithValue("$device", deviceId);
            delete.ExecuteNonQuery();
        }

        foreach (var app in apps)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO mobile_app_inventory(
                    device_id, package_name, app_name, version_name,
                    version_code, installer_package, system_app, sideloaded,
                    requested_permissions_json, first_install_time,
                    last_update_time, sha256, observed_at)
                VALUES($device,$package,$name,$version,$versionCode,$installer,
                    $system,$sideloaded,$permissions,$first,$updated,$sha,$observed);
                """;
            command.Parameters.AddWithValue("$device", deviceId);
            command.Parameters.AddWithValue("$package", app.PackageName);
            command.Parameters.AddWithValue("$name", app.AppName);
            command.Parameters.AddWithValue("$version", app.VersionName);
            command.Parameters.AddWithValue("$versionCode", app.VersionCode);
            command.Parameters.AddWithValue("$installer", app.InstallerPackage);
            command.Parameters.AddWithValue("$system", app.SystemApp ? 1 : 0);
            command.Parameters.AddWithValue("$sideloaded", app.Sideloaded ? 1 : 0);
            command.Parameters.AddWithValue("$permissions", JsonSerializer.Serialize(app.RequestedPermissions));
            command.Parameters.AddWithValue("$first", SafeTime(app.FirstInstallTime).ToString("O"));
            command.Parameters.AddWithValue("$updated", SafeTime(app.LastUpdateTime).ToString("O"));
            command.Parameters.AddWithValue("$sha", app.Sha256);
            command.Parameters.AddWithValue("$observed", observedAt.ToString("O"));
            command.ExecuteNonQuery();
        }

        AuditSql.Insert(
            connection,
            transaction,
            "mobile-device",
            "mobile.inventory.recorded",
            "mobile_device",
            deviceId,
            true,
            JsonSerializer.Serialize(new { Apps = apps.Count, ObservedAt = observedAt }));
        transaction.Commit();
    }

    public void AddFindings(
        string deviceId,
        IReadOnlyCollection<MobileSecurityFindingDto> findings,
        DateTimeOffset observedAt)
    {
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        foreach (var finding in findings)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO mobile_security_findings(
                    finding_id, device_id, observed_at, severity, risk_score,
                    category, title, detail, entity_type, entity_id, status)
                VALUES($id,$device,$observed,$severity,$risk,$category,$title,
                    $detail,$entityType,$entityId,$status)
                ON CONFLICT(finding_id) DO UPDATE SET
                    observed_at=excluded.observed_at,
                    severity=excluded.severity,
                    risk_score=excluded.risk_score,
                    category=excluded.category,
                    title=excluded.title,
                    detail=excluded.detail,
                    entity_type=excluded.entity_type,
                    entity_id=excluded.entity_id,
                    status=excluded.status;
                """;
            command.Parameters.AddWithValue("$id", finding.FindingId);
            command.Parameters.AddWithValue("$device", deviceId);
            command.Parameters.AddWithValue("$observed", SafeTime(finding.ObservedAt).ToString("O"));
            command.Parameters.AddWithValue("$severity", finding.Severity);
            command.Parameters.AddWithValue("$risk", finding.RiskScore);
            command.Parameters.AddWithValue("$category", finding.Category);
            command.Parameters.AddWithValue("$title", finding.Title);
            command.Parameters.AddWithValue("$detail", finding.Detail);
            command.Parameters.AddWithValue("$entityType", finding.EntityType);
            command.Parameters.AddWithValue("$entityId", finding.EntityId);
            command.Parameters.AddWithValue("$status", finding.Status);
            command.ExecuteNonQuery();
        }

        AuditSql.Insert(
            connection,
            transaction,
            "mobile-device",
            "mobile.findings.recorded",
            "mobile_device",
            deviceId,
            true,
            JsonSerializer.Serialize(new { Findings = findings.Count, ObservedAt = observedAt }));
        transaction.Commit();
    }

    private static Risk ScoreHeartbeat(MobileHeartbeatRequest request)
    {
        var score = 0;
        var reasons = new List<string>();
        if (!request.ScreenLockEnabled)
        {
            score += 25;
            reasons.Add("screen lock disabled");
        }
        if (request.DeveloperModeEnabled)
        {
            score += 20;
            reasons.Add("developer mode enabled");
        }
        if (request.UsbDebuggingEnabled)
        {
            score += 25;
            reasons.Add("USB debugging enabled");
        }
        if (request.UnknownSourcesEnabled)
        {
            score += 25;
            reasons.Add("unknown-source installs enabled");
        }
        if (!request.VpnActive)
        {
            score += 5;
            reasons.Add("VPN/DNS protection inactive");
        }

        return new Risk(Math.Clamp(score, 0, 100), reasons.Count == 0
            ? "No mobile posture concerns reported."
            : string.Join(", ", reasons));
    }

    private static IReadOnlyList<MobileDeviceDto> ReadDevices(
        SqliteConnection connection,
        int limit)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT device_id, display_name, platform, manufacturer, model,
                   os_version, app_version, status, first_seen_at,
                   last_seen_at, last_heartbeat_at, risk_score, risk_reason
            FROM mobile_devices
            ORDER BY last_seen_at DESC
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$limit", limit);
        using var reader = command.ExecuteReader();
        var rows = new List<MobileDeviceDto>();
        while (reader.Read()) rows.Add(ReadDevice(reader));
        return rows;
    }

    private static MobileDeviceDto? ReadDeviceById(
        SqliteConnection connection,
        string deviceId)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT device_id, display_name, platform, manufacturer, model,
                   os_version, app_version, status, first_seen_at,
                   last_seen_at, last_heartbeat_at, risk_score, risk_reason
            FROM mobile_devices
            WHERE device_id=$device;
            """;
        command.Parameters.AddWithValue("$device", deviceId);
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadDevice(reader) : null;
    }

    private static MobileDeviceDto ReadDevice(SqliteDataReader reader) => new(
        reader.GetString(0),
        reader.GetString(1),
        reader.GetString(2),
        reader.GetString(3),
        reader.GetString(4),
        reader.GetString(5),
        reader.GetString(6),
        reader.GetString(7),
        DateTimeOffset.Parse(reader.GetString(8)),
        DateTimeOffset.Parse(reader.GetString(9)),
        reader.IsDBNull(10) ? null : DateTimeOffset.Parse(reader.GetString(10)),
        reader.GetInt32(11),
        reader.GetString(12));

    private static IReadOnlyList<MobileAppInventoryItemDto> ReadRecentApps(
        SqliteConnection connection,
        int limit)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT package_name, app_name, version_name, version_code,
                   installer_package, system_app, sideloaded,
                   requested_permissions_json, first_install_time,
                   last_update_time, sha256
            FROM mobile_app_inventory
            ORDER BY observed_at DESC
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$limit", limit);
        using var reader = command.ExecuteReader();
        var rows = new List<MobileAppInventoryItemDto>();
        while (reader.Read())
        {
            rows.Add(new MobileAppInventoryItemDto(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetInt64(3),
                reader.GetString(4),
                reader.GetInt64(5) == 1,
                reader.GetInt64(6) == 1,
                JsonSerializer.Deserialize<IReadOnlyList<string>>(reader.GetString(7)) ?? [],
                DateTimeOffset.Parse(reader.GetString(8)),
                DateTimeOffset.Parse(reader.GetString(9)),
                reader.GetString(10)));
        }
        return rows;
    }

    private static IReadOnlyList<MobileSecurityFindingDto> ReadFindings(
        SqliteConnection connection,
        int limit)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT finding_id, observed_at, severity, risk_score, category,
                   title, detail, entity_type, entity_id, status
            FROM mobile_security_findings
            ORDER BY observed_at DESC
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$limit", limit);
        using var reader = command.ExecuteReader();
        var rows = new List<MobileSecurityFindingDto>();
        while (reader.Read())
        {
            rows.Add(new MobileSecurityFindingDto(
                reader.GetString(0),
                DateTimeOffset.Parse(reader.GetString(1)),
                reader.GetString(2),
                reader.GetInt32(3),
                reader.GetString(4),
                reader.GetString(5),
                reader.GetString(6),
                reader.GetString(7),
                reader.GetString(8),
                reader.GetString(9)));
        }
        return rows;
    }

    private static IReadOnlyList<MobileNetworkEventDto> ReadNetworkEvents(
        SqliteConnection connection,
        int limit)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT event_id, device_id, observed_at, protocol, destination_host,
                   destination_ip, destination_port, app_package, verdict,
                   risk_score
            FROM mobile_network_events
            ORDER BY observed_at DESC
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$limit", limit);
        using var reader = command.ExecuteReader();
        var rows = new List<MobileNetworkEventDto>();
        while (reader.Read())
        {
            rows.Add(new MobileNetworkEventDto(
                reader.GetString(0),
                reader.GetString(1),
                DateTimeOffset.Parse(reader.GetString(2)),
                reader.GetString(3),
                reader.GetString(4),
                reader.GetString(5),
                reader.GetInt32(6),
                reader.GetString(7),
                reader.GetString(8),
                reader.GetInt32(9)));
        }
        return rows;
    }

    private static MobilePolicyDto ReadPolicy(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT require_vpn, alert_on_sideloaded_apps,
                   alert_on_developer_mode, risky_permission_threshold,
                   blocked_packages_json
            FROM mobile_policy
            WHERE policy_id='default';
            """;
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return new MobilePolicyDto(false, true, true, 12, []);
        }

        return new MobilePolicyDto(
            reader.GetInt64(0) == 1,
            reader.GetInt64(1) == 1,
            reader.GetInt64(2) == 1,
            reader.GetInt32(3),
            JsonSerializer.Deserialize<IReadOnlyList<string>>(reader.GetString(4)) ?? []);
    }

    private static DateTimeOffset SafeTime(DateTimeOffset value) =>
        value == default ? DateTimeOffset.UtcNow : value;
}