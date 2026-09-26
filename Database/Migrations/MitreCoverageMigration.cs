namespace RoamSentinel.Database.Migrations;

public sealed class MitreCoverageMigration : IDatabaseMigration
{
    public long Version => 2026070405;
    public string Name => "mitre_attack_coverage_and_events";

    public string Sql => """
        ALTER TABLE mitre_mappings
            ADD COLUMN mapping_type TEXT NOT NULL DEFAULT 'Direct';

        CREATE TABLE IF NOT EXISTS mitre_techniques (
            technique_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            primary_tactic TEXT NOT NULL,
            status TEXT NOT NULL,
            replaced_by TEXT NULL,
            url TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS detection_findings (
            finding_id TEXT PRIMARY KEY,
            rule_id TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            host TEXT NOT NULL,
            severity TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            evidence TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            occurrence_count INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY(rule_id) REFERENCES detection_rules(rule_id)
                ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS ix_detection_findings_last_seen
            ON detection_findings(last_seen_at DESC);
        CREATE INDEX IF NOT EXISTS ix_detection_findings_rule
            ON detection_findings(rule_id, last_seen_at DESC);
        CREATE INDEX IF NOT EXISTS ix_detection_findings_host
            ON detection_findings(host, last_seen_at DESC);

        INSERT INTO mitre_techniques (
            technique_id, name, primary_tactic, status, replaced_by, url,
            updated_at
        ) VALUES
            ('T1059', 'Command and Scripting Interpreter', 'Execution',
             'Current', NULL, 'https://attack.mitre.org/techniques/T1059/',
             datetime('now')),
            ('T1547', 'Boot or Logon Autostart Execution', 'Persistence',
             'Current', NULL, 'https://attack.mitre.org/techniques/T1547/',
             datetime('now')),
            ('T1053', 'Scheduled Task/Job', 'Persistence',
             'Current', NULL, 'https://attack.mitre.org/techniques/T1053/',
             datetime('now')),
            ('T1003', 'OS Credential Dumping', 'Credential Access',
             'Current', NULL, 'https://attack.mitre.org/techniques/T1003/',
             datetime('now')),
            ('T1021', 'Remote Services', 'Lateral Movement',
             'Current', NULL, 'https://attack.mitre.org/techniques/T1021/',
             datetime('now')),
            ('T1105', 'Ingress Tool Transfer', 'Command and Control',
             'Current', NULL, 'https://attack.mitre.org/techniques/T1105/',
             datetime('now')),
            ('T1071', 'Application Layer Protocol', 'Command and Control',
             'Current', NULL, 'https://attack.mitre.org/techniques/T1071/',
             datetime('now')),
            ('T1562', 'Impair Defenses', 'Defense Evasion',
             'Legacy', 'T1685', 'https://attack.mitre.org/techniques/T1562/',
             datetime('now')),
            ('T1685', 'Disable or Modify Tools', 'Defense Impairment',
             'Current', NULL, 'https://attack.mitre.org/techniques/T1685/',
             datetime('now')),
            ('T1059.001', 'PowerShell', 'Execution',
             'Current', NULL, 'https://attack.mitre.org/techniques/T1059/001/',
             datetime('now')),
            ('T1547.001', 'Registry Run Keys / Startup Folder', 'Persistence',
             'Current', NULL, 'https://attack.mitre.org/techniques/T1547/001/',
             datetime('now')),
            ('T1053.005', 'Scheduled Task', 'Persistence',
             'Current', NULL, 'https://attack.mitre.org/techniques/T1053/005/',
             datetime('now')),
            ('T1204.002', 'Malicious File', 'Execution',
             'Current', NULL, 'https://attack.mitre.org/techniques/T1204/002/',
             datetime('now')),
            ('T1686.003', 'Windows Host Firewall', 'Defense Impairment',
             'Current', NULL, 'https://attack.mitre.org/techniques/T1686/003/',
             datetime('now'))
        ON CONFLICT(technique_id) DO UPDATE SET
            name = excluded.name,
            primary_tactic = excluded.primary_tactic,
            status = excluded.status,
            replaced_by = excluded.replaced_by,
            url = excluded.url,
            updated_at = excluded.updated_at;

        INSERT INTO mitre_mappings (
            rule_id, tactic, technique_id, technique_name, subtechnique_id,
            mapping_type
        )
        SELECT 'RS-EXEC-001', 'Execution', 'T1059',
               'Command and Scripting Interpreter', NULL, 'Parent'
        WHERE NOT EXISTS (
            SELECT 1 FROM mitre_mappings
            WHERE rule_id = 'RS-EXEC-001' AND technique_id = 'T1059'
        );

        INSERT INTO mitre_mappings (
            rule_id, tactic, technique_id, technique_name, subtechnique_id,
            mapping_type
        )
        SELECT 'RS-PERSIST-001', 'Persistence', 'T1547',
               'Boot or Logon Autostart Execution', NULL, 'Parent'
        WHERE NOT EXISTS (
            SELECT 1 FROM mitre_mappings
            WHERE rule_id = 'RS-PERSIST-001' AND technique_id = 'T1547'
        );

        INSERT INTO mitre_mappings (
            rule_id, tactic, technique_id, technique_name, subtechnique_id,
            mapping_type
        )
        SELECT 'RS-PERSIST-002', 'Persistence', 'T1053',
               'Scheduled Task/Job', NULL, 'Parent'
        WHERE NOT EXISTS (
            SELECT 1 FROM mitre_mappings
            WHERE rule_id = 'RS-PERSIST-002' AND technique_id = 'T1053'
        );

        INSERT INTO mitre_mappings (
            rule_id, tactic, technique_id, technique_name, subtechnique_id,
            mapping_type
        )
        SELECT 'RS-DEFENSE-001', 'Defense Evasion', 'T1562',
               'Impair Defenses', NULL, 'Legacy alias'
        WHERE NOT EXISTS (
            SELECT 1 FROM mitre_mappings
            WHERE rule_id = 'RS-DEFENSE-001' AND technique_id = 'T1562'
        );
        """;
}
