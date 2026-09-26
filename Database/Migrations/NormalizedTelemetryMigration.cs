namespace RoamSentinel.Database.Migrations;

public sealed class NormalizedTelemetryMigration : IDatabaseMigration
{
    public long Version => 2026070402;
    public string Name => "normalized_windows_telemetry";

    public string Sql => """
        ALTER TABLE telemetry_processes ADD COLUMN parent_process_id INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE telemetry_processes ADD COLUMN parent_process_name TEXT NOT NULL DEFAULT '';
        ALTER TABLE telemetry_processes ADD COLUMN command_line TEXT NOT NULL DEFAULT '';

        CREATE INDEX IF NOT EXISTS ix_telemetry_processes_parent
            ON telemetry_processes(parent_process_id, observed_at DESC);

        CREATE TABLE IF NOT EXISTS telemetry_scheduled_tasks (
            telemetry_id INTEGER PRIMARY KEY AUTOINCREMENT,
            observed_at TEXT NOT NULL,
            name TEXT NOT NULL,
            task_path TEXT NOT NULL,
            state TEXT NOT NULL,
            enabled INTEGER NOT NULL,
            author TEXT NOT NULL,
            command TEXT NOT NULL,
            arguments TEXT NOT NULL,
            trigger_summary TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_telemetry_tasks_observed
            ON telemetry_scheduled_tasks(observed_at DESC);

        CREATE TABLE IF NOT EXISTS telemetry_services (
            telemetry_id INTEGER PRIMARY KEY AUTOINCREMENT,
            observed_at TEXT NOT NULL,
            name TEXT NOT NULL,
            display_name TEXT NOT NULL,
            state TEXT NOT NULL,
            start_mode TEXT NOT NULL,
            executable_path TEXT NOT NULL,
            process_id INTEGER NOT NULL,
            account TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_telemetry_services_observed
            ON telemetry_services(observed_at DESC);

        CREATE TABLE IF NOT EXISTS telemetry_defender (
            telemetry_id INTEGER PRIMARY KEY AUTOINCREMENT,
            observed_at TEXT NOT NULL,
            service_enabled INTEGER NOT NULL,
            antivirus_enabled INTEGER NOT NULL,
            realtime_enabled INTEGER NOT NULL,
            network_inspection_enabled INTEGER NOT NULL,
            quick_scan_age INTEGER NULL,
            full_scan_age INTEGER NULL,
            signature_updated_at TEXT NULL,
            signature_version TEXT NOT NULL,
            message TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_telemetry_defender_observed
            ON telemetry_defender(observed_at DESC);

        CREATE TABLE IF NOT EXISTS telemetry_firewall (
            telemetry_id INTEGER PRIMARY KEY AUTOINCREMENT,
            observed_at TEXT NOT NULL,
            profile_name TEXT NOT NULL,
            enabled INTEGER NOT NULL,
            default_inbound_action TEXT NOT NULL,
            default_outbound_action TEXT NOT NULL,
            notifications_disabled INTEGER NOT NULL,
            available INTEGER NOT NULL,
            message TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_telemetry_firewall_observed
            ON telemetry_firewall(observed_at DESC);

        CREATE TABLE IF NOT EXISTS telemetry_ai_agents (
            telemetry_id INTEGER PRIMARY KEY AUTOINCREMENT,
            observed_at TEXT NOT NULL,
            name TEXT NOT NULL,
            executable_path TEXT NOT NULL,
            version TEXT NOT NULL,
            publisher TEXT NOT NULL,
            source TEXT NOT NULL,
            is_running INTEGER NOT NULL,
            process_id INTEGER NULL
        );
        CREATE INDEX IF NOT EXISTS ix_telemetry_agents_observed
            ON telemetry_ai_agents(observed_at DESC);

        CREATE TABLE IF NOT EXISTS telemetry_suspicious_paths (
            telemetry_id INTEGER PRIMARY KEY AUTOINCREMENT,
            observed_at TEXT NOT NULL,
            path TEXT NOT NULL,
            source_type TEXT NOT NULL,
            source_name TEXT NOT NULL,
            reason TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_telemetry_paths_observed
            ON telemetry_suspicious_paths(observed_at DESC);
        """;
}
