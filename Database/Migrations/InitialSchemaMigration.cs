namespace RoamSentinel.Database.Migrations;

public sealed class InitialSchemaMigration : IDatabaseMigration
{
    public long Version => 2026070401;
    public string Name => "initial_security_platform_schema";

    public string Sql => """
        CREATE TABLE IF NOT EXISTS security_events (
            event_id TEXT PRIMARY KEY,
            occurred_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            detail TEXT NOT NULL,
            occurrence_count INTEGER NOT NULL DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS ix_security_events_occurred_at
            ON security_events(occurred_at DESC);
        CREATE INDEX IF NOT EXISTS ix_security_events_severity
            ON security_events(severity, occurred_at DESC);

        CREATE TABLE IF NOT EXISTS telemetry_processes (
            telemetry_id INTEGER PRIMARY KEY AUTOINCREMENT,
            observed_at TEXT NOT NULL,
            process_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            executable_path TEXT NOT NULL,
            memory_mb REAL NOT NULL,
            private_memory_mb REAL NOT NULL,
            cpu_percent REAL NOT NULL,
            handle_count INTEGER NOT NULL,
            thread_count INTEGER NOT NULL,
            connection_count INTEGER NOT NULL,
            started_at TEXT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_telemetry_processes_observed
            ON telemetry_processes(observed_at DESC);
        CREATE INDEX IF NOT EXISTS ix_telemetry_processes_pid
            ON telemetry_processes(process_id, observed_at DESC);

        CREATE TABLE IF NOT EXISTS telemetry_network (
            telemetry_id INTEGER PRIMARY KEY AUTOINCREMENT,
            observed_at TEXT NOT NULL,
            protocol TEXT NOT NULL,
            local_address TEXT NOT NULL,
            local_port INTEGER NOT NULL,
            remote_address TEXT NOT NULL,
            remote_port INTEGER NOT NULL,
            state TEXT NOT NULL,
            process_id INTEGER NOT NULL,
            process_name TEXT NOT NULL,
            process_path TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_telemetry_network_observed
            ON telemetry_network(observed_at DESC);
        CREATE INDEX IF NOT EXISTS ix_telemetry_network_remote
            ON telemetry_network(remote_address, remote_port);

        CREATE TABLE IF NOT EXISTS telemetry_startup (
            telemetry_id INTEGER PRIMARY KEY AUTOINCREMENT,
            observed_at TEXT NOT NULL,
            name TEXT NOT NULL,
            command TEXT NOT NULL,
            source TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_telemetry_startup_observed
            ON telemetry_startup(observed_at DESC);

        CREATE TABLE IF NOT EXISTS detection_rules (
            rule_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            severity TEXT NOT NULL,
            confidence INTEGER NOT NULL DEFAULT 50,
            configuration_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS threat_indicators (
            indicator TEXT NOT NULL,
            indicator_type TEXT NOT NULL,
            reputation TEXT NOT NULL,
            confidence INTEGER NOT NULL,
            source TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            expires_at TEXT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            PRIMARY KEY(indicator, source)
        );
        CREATE INDEX IF NOT EXISTS ix_threat_indicators_expiry
            ON threat_indicators(expires_at);

        CREATE TABLE IF NOT EXISTS mitre_mappings (
            mapping_id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id TEXT NOT NULL,
            tactic TEXT NOT NULL,
            technique_id TEXT NOT NULL,
            technique_name TEXT NOT NULL,
            subtechnique_id TEXT NULL,
            FOREIGN KEY(rule_id) REFERENCES detection_rules(rule_id)
                ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS ix_mitre_mappings_rule
            ON mitre_mappings(rule_id);

        CREATE TABLE IF NOT EXISTS response_actions (
            action_id TEXT PRIMARY KEY,
            requested_at TEXT NOT NULL,
            completed_at TEXT NOT NULL,
            action_type TEXT NOT NULL,
            target TEXT NOT NULL,
            status TEXT NOT NULL,
            success INTEGER NOT NULL,
            output TEXT NOT NULL,
            error TEXT NOT NULL,
            requested_by TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_response_actions_requested
            ON response_actions(requested_at DESC);

        CREATE TABLE IF NOT EXISTS agent_registry (
            agent_id INTEGER PRIMARY KEY AUTOINCREMENT,
            executable_path TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL DEFAULT '',
            trust_state TEXT NOT NULL,
            publisher TEXT NOT NULL DEFAULT '',
            executable_hash TEXT NOT NULL DEFAULT '',
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS ix_agent_registry_trust
            ON agent_registry(trust_state);

        CREATE TABLE IF NOT EXISTS agent_activity (
            activity_id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id INTEGER NULL,
            executable_path TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            activity_type TEXT NOT NULL,
            detail_json TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY(agent_id) REFERENCES agent_registry(agent_id)
                ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS ix_agent_activity_occurred
            ON agent_activity(occurred_at DESC);

        CREATE TABLE IF NOT EXISTS audit_log (
            audit_id TEXT PRIMARY KEY,
            occurred_at TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            success INTEGER NOT NULL,
            detail_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_audit_log_occurred
            ON audit_log(occurred_at DESC);
        CREATE INDEX IF NOT EXISTS ix_audit_log_entity
            ON audit_log(entity_type, entity_id, occurred_at DESC);

        CREATE TABLE IF NOT EXISTS system_settings (
            setting_key TEXT PRIMARY KEY,
            setting_value TEXT NOT NULL,
            value_type TEXT NOT NULL DEFAULT 'string',
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ip_blocks (
            ip_address TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            blocked_at TEXT NOT NULL
        );

        INSERT OR IGNORE INTO detection_rules (
            rule_id, name, description, enabled, severity, confidence,
            configuration_json, created_at, updated_at
        ) VALUES
            ('RS-PROC-001', 'Unapproved AI agent network activity',
             'Flags an identified AI/developer agent with network activity before authorization.',
             1, 'High', 80, '{}', datetime('now'), datetime('now')),
            ('RS-PERSIST-001', 'User-writable persistence',
             'Flags persistence commands executing from user-writable paths.',
             1, 'Medium', 65, '{}', datetime('now'), datetime('now')),
            ('RS-NET-001', 'Sensitive remote port',
             'Raises risk for connections to configured sensitive remote ports.',
             1, 'Medium', 55, '{}', datetime('now'), datetime('now'));

        INSERT OR IGNORE INTO mitre_mappings (
            rule_id, tactic, technique_id, technique_name, subtechnique_id
        ) VALUES
            ('RS-PROC-001', 'Command and Control', 'T1071',
             'Application Layer Protocol', NULL),
            ('RS-PERSIST-001', 'Persistence', 'T1053',
             'Scheduled Task/Job', NULL),
            ('RS-NET-001', 'Command and Control', 'T1043',
             'Commonly Used Port', NULL);

        INSERT OR IGNORE INTO system_settings (
            setting_key, setting_value, value_type, updated_at
        ) VALUES
            ('schema.version', '2026070401', 'integer', datetime('now')),
            ('product.name', 'RoamSentinel', 'string', datetime('now'));
        """;
}
