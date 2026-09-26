namespace RoamSentinel.Database.Migrations;

public sealed class ResponseControlMigration : IDatabaseMigration
{
    public long Version => 2026070407;
    public string Name => "controlled_response_engine";

    public string Sql => """
        ALTER TABLE response_actions
            ADD COLUMN before_json TEXT NOT NULL DEFAULT '{}';
        ALTER TABLE response_actions
            ADD COLUMN after_json TEXT NOT NULL DEFAULT '{}';

        ALTER TABLE security_events
            ADD COLUMN status TEXT NOT NULL DEFAULT 'open';
        ALTER TABLE security_events
            ADD COLUMN resolution_note TEXT NOT NULL DEFAULT '';
        ALTER TABLE security_events
            ADD COLUMN resolved_at TEXT NULL;
        ALTER TABLE security_events
            ADD COLUMN resolved_by TEXT NOT NULL DEFAULT '';

        CREATE INDEX IF NOT EXISTS ix_security_events_status
            ON security_events(status, occurred_at DESC);

        CREATE TABLE IF NOT EXISTS disabled_startup_items (
            disable_id TEXT PRIMARY KEY,
            source_type TEXT NOT NULL,
            source TEXT NOT NULL,
            item_name TEXT NOT NULL,
            original_value TEXT NOT NULL,
            backup_path TEXT NOT NULL DEFAULT '',
            disabled_at TEXT NOT NULL,
            disabled_by TEXT NOT NULL,
            restored_at TEXT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_disabled_startup_items_disabled
            ON disabled_startup_items(disabled_at DESC);
        """;
}
