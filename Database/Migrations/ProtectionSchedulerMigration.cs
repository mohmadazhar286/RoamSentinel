namespace RoamSentinel.Database.Migrations;

public sealed class ProtectionSchedulerMigration : IDatabaseMigration
{
    public long Version => 2026081001;
    public string Name => "protection_scheduler";
    public string Sql => """
        CREATE TABLE protection_scheduler_tasks (
            task_key TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            enabled INTEGER NOT NULL,
            interval_seconds INTEGER NOT NULL,
            last_started_at TEXT NULL,
            last_completed_at TEXT NULL,
            next_run_at TEXT NULL,
            last_success INTEGER NOT NULL DEFAULT 0,
            last_status TEXT NOT NULL DEFAULT 'pending',
            last_message TEXT NOT NULL DEFAULT '',
            success_count INTEGER NOT NULL DEFAULT 0,
            failure_count INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX ix_protection_scheduler_next_run
            ON protection_scheduler_tasks(enabled, next_run_at);
        """;
}
