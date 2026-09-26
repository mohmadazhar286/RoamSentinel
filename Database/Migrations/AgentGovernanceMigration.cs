namespace RoamSentinel.Database.Migrations;

public sealed class AgentGovernanceMigration : IDatabaseMigration
{
    public long Version => 2026070408;
    public string Name => "ai_agent_governance";

    public string Sql => """
        ALTER TABLE agent_registry
            ADD COLUMN agent_key TEXT NOT NULL DEFAULT '';
        ALTER TABLE agent_registry
            ADD COLUMN is_running INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE agent_registry
            ADD COLUMN process_id INTEGER NULL;
        ALTER TABLE agent_registry
            ADD COLUMN network_connection_count INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE agent_registry
            ADD COLUMN distinct_remote_address_count INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE agent_registry
            ADD COLUMN network_last_seen TEXT NULL;
        ALTER TABLE agent_registry
            ADD COLUMN risk_score INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE agent_registry
            ADD COLUMN risk_reason TEXT NOT NULL DEFAULT '';
        ALTER TABLE agent_registry
            ADD COLUMN network_authorized INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE agent_registry
            ADD COLUMN can_enforce_path INTEGER NOT NULL DEFAULT 1;

        UPDATE agent_registry
        SET trust_state = 'trusted',
            network_authorized = 1
        WHERE trust_state = 'authorized';

        CREATE INDEX IF NOT EXISTS ix_agent_registry_risk
            ON agent_registry(risk_score DESC, last_seen_at DESC);
        CREATE INDEX IF NOT EXISTS ix_agent_registry_key
            ON agent_registry(agent_key, last_seen_at DESC);

        CREATE TABLE IF NOT EXISTS agent_catalog (
            agent_key TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            vendor TEXT NOT NULL,
            identity_markers_json TEXT NOT NULL,
            trusted_path_markers_json TEXT NOT NULL,
            shared_host INTEGER NOT NULL DEFAULT 0,
            enabled INTEGER NOT NULL DEFAULT 1
        );

        INSERT OR IGNORE INTO agent_catalog (
            agent_key, display_name, vendor, identity_markers_json,
            trusted_path_markers_json, shared_host
        ) VALUES
            ('chatgpt-desktop', 'ChatGPT Desktop', 'OpenAI',
             '["chatgpt"]',
             '["\\program files\\windowsapps\\openai.chatgpt","\\appdata\\local\\packages\\openai.chatgpt"]', 0),
            ('claude-desktop', 'Claude Desktop', 'Anthropic',
             '["claude","anthropic"]',
             '["\\appdata\\local\\anthropicclaude\\","\\appdata\\local\\programs\\claude\\"]', 0),
            ('cursor', 'Cursor', 'Anysphere',
             '["cursor"]',
             '["\\appdata\\local\\programs\\cursor\\","\\program files\\cursor\\"]', 0),
            ('windsurf', 'Windsurf', 'Codeium',
             '["windsurf"]',
             '["\\appdata\\local\\programs\\windsurf\\","\\program files\\windsurf\\"]', 0),
            ('cline', 'Cline', 'Cline',
             '["saoudrizwan.claude-dev","cline"]',
             '["\\.vscode\\extensions\\saoudrizwan.claude-dev","\\.vscode\\extensions\\cline"]', 1),
            ('roo-code', 'Roo Code', 'Roo Code',
             '["roo-cline","roo-code","roo code"]',
             '["\\.vscode\\extensions\\rooveterinaryinc.roo-cline","\\.vscode\\extensions\\roo-cline"]', 1),
            ('aider', 'Aider', 'Aider-AI',
             '["aider"]',
             '["\\python\\scripts\\aider","\\pipx\\venvs\\aider"]', 1),
            ('openhands', 'OpenHands', 'All Hands AI',
             '["openhands","open-hands"]',
             '[]', 1),
            ('vscode-copilot', 'VS Code Copilot', 'GitHub',
             '["github.copilot","copilot-language-server"]',
             '["\\.vscode\\extensions\\github.copilot"]', 1),
            ('codex', 'Codex', 'OpenAI',
             '["codex"]',
             '["\\appdata\\roaming\\npm\\codex","\\appdata\\local\\openai\\codex"]', 1);

        INSERT INTO detection_rules (
            rule_id, name, description, enabled, severity, confidence,
            configuration_json, created_at, updated_at, category, risk_weight
        ) VALUES
            ('RS-AGENT-BLOCK-001', 'Blocked AI agent is running',
             'Detects a blocked AI agent with an active process.',
             1, 'Critical', 100, '{}', datetime('now'), datetime('now'),
             'Agent Governance', 100),
            ('RS-AGENT-NET-001', 'AI agent unusual network activity',
             'Detects an AI agent using unusual public destinations or ports.',
             1, 'High', 90, '{}', datetime('now'), datetime('now'),
             'Agent Governance', 80)
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
            ('RS-AGENT-BLOCK-001', 'Execution', 'T1204.002',
             'User Execution: Malicious File', 'T1204.002', 'Behavioral'),
            ('RS-AGENT-NET-001', 'Command and Control', 'T1071',
             'Application Layer Protocol', NULL, 'Behavioral');
        """;
}
