namespace RoamSentinel.Database.Migrations;

public sealed class UnifiedDetectionMigration : IDatabaseMigration
{
    public long Version => 2026070403;
    public string Name => "unified_detection_rules";

    public string Sql => """
        ALTER TABLE detection_rules
            ADD COLUMN category TEXT NOT NULL DEFAULT 'General';
        ALTER TABLE detection_rules
            ADD COLUMN risk_weight INTEGER NOT NULL DEFAULT 50;

        CREATE INDEX IF NOT EXISTS ix_detection_rules_enabled_category
            ON detection_rules(enabled, category);

        INSERT INTO detection_rules (
            rule_id, name, description, enabled, severity, confidence,
            configuration_json, created_at, updated_at, category, risk_weight
        ) VALUES
            ('RS-EXEC-001', 'PowerShell encoded command',
             'Detects PowerShell or pwsh launched with an encoded-command argument.',
             1, 'Critical', 90, '{"arguments":["-enc","-encodedcommand"]}',
             datetime('now'), datetime('now'), 'Execution', 90),
            ('RS-PROC-002', 'Executable launched from temporary directory',
             'Detects a running executable launched from a configured temporary path.',
             1, 'High', 75, '{"pathMarkers":["\\temp\\"]}',
             datetime('now'), datetime('now'), 'Execution', 65),
            ('RS-NET-002', 'Unknown executable with network activity',
             'Detects network-active processes whose executable path is unavailable.',
             1, 'Medium', 55, '{}',
             datetime('now'), datetime('now'), 'Network', 45),
            ('RS-PERSIST-001', 'Suspicious startup persistence',
             'Detects Run-key or startup-folder entries using scripts or user-writable paths.',
             1, 'High', 75, '{}',
             datetime('now'), datetime('now'), 'Persistence', 60),
            ('RS-PERSIST-002', 'Suspicious scheduled task persistence',
             'Detects enabled scheduled tasks invoking scripts or user-writable paths.',
             1, 'High', 80, '{}',
             datetime('now'), datetime('now'), 'Persistence', 70),
            ('RS-PROC-001', 'AI agent executing from untrusted path',
             'Detects a running AI agent whose executable path is not explicitly authorized.',
             1, 'High', 85, '{}',
             datetime('now'), datetime('now'), 'Agent Governance', 80),
            ('RS-NET-003', 'Process connected to suspicious IP',
             'Detects a process connection to an active suspicious or malicious IP indicator.',
             1, 'Critical', 95, '{}',
             datetime('now'), datetime('now'), 'Threat Intelligence', 95),
            ('RS-DEFENSE-001', 'Microsoft Defender disabled',
             'Detects disabled antivirus or real-time Microsoft Defender protection.',
             1, 'Critical', 100, '{}',
             datetime('now'), datetime('now'), 'Defense Impairment', 100),
            ('RS-DEFENSE-002', 'Windows Firewall profile disabled',
             'Detects one or more disabled Windows Firewall profiles.',
             1, 'Critical', 95, '{}',
             datetime('now'), datetime('now'), 'Defense Impairment', 95)
        ON CONFLICT(rule_id) DO UPDATE SET
            name = excluded.name,
            description = excluded.description,
            severity = excluded.severity,
            confidence = excluded.confidence,
            configuration_json = excluded.configuration_json,
            updated_at = excluded.updated_at,
            category = excluded.category,
            risk_weight = excluded.risk_weight;

        UPDATE detection_rules
        SET enabled = 0, updated_at = datetime('now')
        WHERE rule_id = 'RS-NET-001';

        DELETE FROM mitre_mappings
        WHERE rule_id IN (
            'RS-EXEC-001', 'RS-PROC-002', 'RS-NET-002',
            'RS-PERSIST-001', 'RS-PERSIST-002', 'RS-PROC-001',
            'RS-NET-003', 'RS-DEFENSE-001', 'RS-DEFENSE-002'
        );

        INSERT INTO mitre_mappings (
            rule_id, tactic, technique_id, technique_name, subtechnique_id
        ) VALUES
            ('RS-EXEC-001', 'Execution', 'T1059.001',
             'Command and Scripting Interpreter: PowerShell', 'T1059.001'),
            ('RS-PROC-002', 'Execution', 'T1204.002',
             'User Execution: Malicious File', 'T1204.002'),
            ('RS-NET-002', 'Command and Control', 'T1071',
             'Application Layer Protocol', NULL),
            ('RS-PERSIST-001', 'Persistence', 'T1547.001',
             'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder',
             'T1547.001'),
            ('RS-PERSIST-002', 'Persistence', 'T1053.005',
             'Scheduled Task/Job: Scheduled Task', 'T1053.005'),
            ('RS-PROC-001', 'Execution', 'T1204.002',
             'User Execution: Malicious File', 'T1204.002'),
            ('RS-NET-003', 'Command and Control', 'T1071',
             'Application Layer Protocol', NULL),
            ('RS-DEFENSE-001', 'Defense Impairment', 'T1685',
             'Disable or Modify Tools', NULL),
            ('RS-DEFENSE-002', 'Defense Impairment', 'T1686.003',
             'Disable or Modify System Firewall: Windows Host Firewall',
             'T1686.003');
        """;
}
