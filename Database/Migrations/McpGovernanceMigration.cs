namespace RoamSentinel.Database.Migrations;

public sealed class McpGovernanceMigration : IDatabaseMigration
{
    public long Version => 2026092702;
    public string Name => "mcp_governance";

    public string Sql => """
        CREATE TABLE IF NOT EXISTS mcp_tool_events (
            event_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            agent_key TEXT NOT NULL,
            server_name TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            arguments_json TEXT NOT NULL,
            result_summary TEXT NOT NULL DEFAULT '',
            risk_score INTEGER NOT NULL,
            severity TEXT NOT NULL,
            verdict TEXT NOT NULL,
            policy_reason TEXT NOT NULL,
            process_id INTEGER,
            client_host TEXT NOT NULL DEFAULT '127.0.0.1'
        );
        CREATE INDEX IF NOT EXISTS ix_mcp_tool_events_timestamp
            ON mcp_tool_events(timestamp DESC);
        CREATE INDEX IF NOT EXISTS ix_mcp_tool_events_agent
            ON mcp_tool_events(agent_key);
        CREATE INDEX IF NOT EXISTS ix_mcp_tool_events_tool
            ON mcp_tool_events(tool_name);

        INSERT INTO detection_rules (
            rule_id, name, description, enabled, severity, confidence,
            configuration_json, created_at, updated_at, category, risk_weight
        ) VALUES
            ('RS-AGENT-MCP-001', 'AI agent invoked high-risk or destructive MCP tool',
             'Detects an autonomous agent using Model Context Protocol (MCP) to execute unvetted shell commands, alter critical system files, or access sensitive credentials.',
             1, 'High', 85, '{}', datetime('now'), datetime('now'),
             'Agent Governance', 85)
        ON CONFLICT(rule_id) DO UPDATE SET
            name = excluded.name,
            description = excluded.description,
            severity = excluded.severity,
            confidence = excluded.confidence,
            category = excluded.category,
            risk_weight = excluded.risk_weight,
            updated_at = excluded.updated_at;

        INSERT OR IGNORE INTO mitre_mappings (
            rule_id, tactic, technique_id, technique_name, subtechnique_id,
            mapping_type
        ) VALUES
            ('RS-AGENT-MCP-001', 'Execution', 'T1059.001',
             'Command and Scripting Interpreter: PowerShell', 'T1059.001', 'Behavioral'),
            ('RS-AGENT-MCP-001', 'Defense Evasion', 'T1562.001',
             'Impair Defenses: Disable or Modify Tools', 'T1562.001', 'Behavioral'),
            ('RS-AGENT-MCP-001', 'Credential Access', 'T1552',
             'Unsecured Credentials', NULL, 'Behavioral');
        """;
}
