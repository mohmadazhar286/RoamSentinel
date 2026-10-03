namespace RoamSentinel.Database.Migrations;

public sealed class AgentGovernanceExpansionMigration : IDatabaseMigration
{
    public long Version => 2026092701;
    public string Name => "agent_governance_expansion";

    public string Sql => """
        INSERT OR IGNORE INTO agent_catalog (
            agent_key, display_name, vendor, identity_markers_json,
            trusted_path_markers_json, shared_host
        ) VALUES
            ('claude-code', 'Claude Code', 'Anthropic',
             '["@anthropic-ai/claude-code","claude-code","claude.cmd"]',
             '["\\npm\\node_modules\\@anthropic-ai\\claude-code","\\appdata\\roaming\\npm\\claude","\\appdata\\local\\programs\\claude-code"]', 1),
            ('antigravity', 'Google Antigravity', 'Google',
             '["antigravity","agy","@google/antigravity"]',
             '["\\.gemini\\antigravity","\\appdata\\local\\programs\\antigravity","\\npm\\node_modules\\@google\\antigravity"]', 1),
            ('continue-dev', 'Continue', 'Continue.dev',
             '["continue.continue","continue-dev"]',
             '["\\.vscode\\extensions\\continue.continue","\\.continue\\"]', 1),
            ('goose-ai', 'Goose', 'Block',
             '["goose-ai","block-goose","goose.exe"]',
             '["\\appdata\\local\\block\\goose","\\program files\\goose"]', 0),
            ('mcp-server', 'MCP Server', 'Model Context Protocol',
             '["@modelcontextprotocol/server-","mcp-server-","mcp_server","uvx mcp-"]',
             '["\\node_modules\\@modelcontextprotocol","\\uv\\tools\\mcp-","\\python\\site-packages\\mcp"]', 1);

        INSERT INTO detection_rules (
            rule_id, name, description, enabled, severity, confidence,
            configuration_json, created_at, updated_at, category, risk_weight
        ) VALUES
            ('RS-AGENT-CHILD-001', 'AI agent spawned suspicious child process',
             'Detects an AI agent process spawning a suspicious shell, script interpreter, downloader, or defense impairment command.',
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
            ('RS-AGENT-CHILD-001', 'Execution', 'T1059.001',
             'Command and Scripting Interpreter: PowerShell', 'T1059.001', 'Behavioral'),
            ('RS-AGENT-CHILD-001', 'Execution', 'T1204.002',
             'User Execution: Malicious File', 'T1204.002', 'Behavioral'),
            ('RS-AGENT-CHILD-001', 'Command and Control', 'T1105',
             'Ingress Tool Transfer', NULL, 'Behavioral');

        CREATE TABLE IF NOT EXISTS agent_egress_rules (
            rule_id TEXT PRIMARY KEY,
            agent_key TEXT NOT NULL,
            executable_path TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            direction TEXT NOT NULL DEFAULT 'Outbound',
            action TEXT NOT NULL DEFAULT 'Block',
            created_at TEXT NOT NULL,
            created_by TEXT NOT NULL DEFAULT 'Administrator'
        );
        CREATE INDEX IF NOT EXISTS ix_agent_egress_rules_key
            ON agent_egress_rules(agent_key);

        CREATE TABLE IF NOT EXISTS codegate_active_rules (
            rule_id TEXT PRIMARY KEY,
            bundle_id TEXT NOT NULL,
            name TEXT NOT NULL,
            severity TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            pattern TEXT NOT NULL,
            explanation TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_codegate_active_rules_bundle
            ON codegate_active_rules(bundle_id);
        """;
}
