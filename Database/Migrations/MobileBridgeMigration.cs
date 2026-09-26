namespace RoamSentinel.Database.Migrations;

public sealed class MobileBridgeMigration : IDatabaseMigration
{
    public long Version => 2026071601;
    public string Name => "mobile_bridge_foundation";
    public string Sql => """
        CREATE TABLE mobile_devices (
            device_id TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            platform TEXT NOT NULL,
            manufacturer TEXT NOT NULL,
            model TEXT NOT NULL,
            os_version TEXT NOT NULL,
            app_version TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('trusted','unknown','blocked')),
            token_hash TEXT NOT NULL UNIQUE,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            last_heartbeat_at TEXT NULL,
            risk_score INTEGER NOT NULL,
            risk_reason TEXT NOT NULL
        );
        CREATE INDEX ix_mobile_devices_last_seen
            ON mobile_devices(last_seen_at DESC);

        CREATE TABLE mobile_pairing_sessions (
            pairing_id TEXT PRIMARY KEY,
            code_hash TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('active','used','expired','revoked')),
            created_by TEXT NOT NULL,
            used_by_device_id TEXT NULL,
            used_at TEXT NULL,
            FOREIGN KEY(used_by_device_id) REFERENCES mobile_devices(device_id)
        );
        CREATE INDEX ix_mobile_pairing_active
            ON mobile_pairing_sessions(status, expires_at);

        CREATE TABLE mobile_app_inventory (
            device_id TEXT NOT NULL,
            package_name TEXT NOT NULL,
            app_name TEXT NOT NULL,
            version_name TEXT NOT NULL,
            version_code INTEGER NOT NULL,
            installer_package TEXT NOT NULL,
            system_app INTEGER NOT NULL,
            sideloaded INTEGER NOT NULL,
            requested_permissions_json TEXT NOT NULL,
            first_install_time TEXT NOT NULL,
            last_update_time TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            PRIMARY KEY(device_id, package_name),
            FOREIGN KEY(device_id) REFERENCES mobile_devices(device_id) ON DELETE CASCADE
        );
        CREATE INDEX ix_mobile_app_inventory_observed
            ON mobile_app_inventory(observed_at DESC);

        CREATE TABLE mobile_security_findings (
            finding_id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            severity TEXT NOT NULL CHECK(severity IN ('info','low','medium','high','critical')),
            risk_score INTEGER NOT NULL,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            detail TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            status TEXT NOT NULL,
            FOREIGN KEY(device_id) REFERENCES mobile_devices(device_id) ON DELETE CASCADE
        );
        CREATE INDEX ix_mobile_security_findings_device_time
            ON mobile_security_findings(device_id, observed_at DESC);
        CREATE INDEX ix_mobile_security_findings_status
            ON mobile_security_findings(status, severity);

        CREATE TABLE mobile_network_events (
            event_id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            protocol TEXT NOT NULL,
            destination_host TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            destination_port INTEGER NOT NULL,
            app_package TEXT NOT NULL,
            verdict TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            FOREIGN KEY(device_id) REFERENCES mobile_devices(device_id) ON DELETE CASCADE
        );
        CREATE INDEX ix_mobile_network_events_time
            ON mobile_network_events(observed_at DESC);

        CREATE TABLE mobile_policy (
            policy_id TEXT PRIMARY KEY,
            require_vpn INTEGER NOT NULL,
            alert_on_sideloaded_apps INTEGER NOT NULL,
            alert_on_developer_mode INTEGER NOT NULL,
            risky_permission_threshold INTEGER NOT NULL,
            blocked_packages_json TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            updated_by TEXT NOT NULL
        );
        INSERT INTO mobile_policy(
            policy_id, require_vpn, alert_on_sideloaded_apps,
            alert_on_developer_mode, risky_permission_threshold,
            blocked_packages_json, updated_at, updated_by)
        VALUES(
            'default', 0, 1, 1, 12, '[]', datetime('now'), 'system');
        """;
}