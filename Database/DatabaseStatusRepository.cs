using RoamSentinel.Core;

namespace RoamSentinel.Database;

public sealed class DatabaseStatusRepository(
    IDatabaseConnectionFactory connections) : IDatabaseStatusRepository
{
    private static readonly string[] RequiredTables =
    [
        "security_events",
        "telemetry_processes",
        "telemetry_network",
        "telemetry_startup",
        "telemetry_scheduled_tasks",
        "telemetry_services",
        "telemetry_defender",
        "telemetry_firewall",
        "telemetry_ai_agents",
        "telemetry_suspicious_paths",
        "detection_rules",
        "threat_indicators",
        "mitre_mappings",
        "mitre_techniques",
        "detection_findings",
        "response_actions",
        "disabled_startup_items",
        "agent_registry",
        "agent_activity",
        "agent_catalog",
        "audit_log",
        "system_settings",
        "device_integrity_inventory",
        "device_integrity_events",
        "device_integrity_findings",
        "mobile_devices",
        "mobile_pairing_sessions",
        "mobile_app_inventory",
        "mobile_security_findings",
        "mobile_network_events",
        "mobile_policy",
        "app_activity_inventory",
        "app_activity_observations",
        "malware_defender_detections",
        "malware_file_observations",
        "codegate_submissions",
        "codegate_findings",
        "codegate_git_pushes",
        "codegate_git_push_files",
        "codegate_offline_bundles",
        "protection_scheduler_tasks",
        "agent_egress_rules",
        "codegate_active_rules",
        "mcp_tool_events"
    ];

    public DatabaseStatusDto GetStatus()
    {
        using var connection = connections.OpenConnection();
        var counts = new Dictionary<string, long>(
            StringComparer.OrdinalIgnoreCase);
        foreach (var table in RequiredTables)
        {
            using var command = connection.CreateCommand();
            command.CommandText = $"SELECT COUNT(*) FROM {table};";
            counts[table] = Convert.ToInt64(command.ExecuteScalar());
        }

        using var migration = connection.CreateCommand();
        migration.CommandText = """
            SELECT COALESCE(MAX(version), 0), COUNT(*)
            FROM schema_migrations;
            """;
        using var reader = migration.ExecuteReader();
        reader.Read();
        return new DatabaseStatusDto(
            "SQLite",
            reader.GetInt64(0),
            reader.GetInt32(1),
            counts);
    }
}
