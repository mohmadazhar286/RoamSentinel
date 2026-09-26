namespace RoamSentinel.Database.Migrations;

public sealed class CodeGateGitTraceabilityMigration : IDatabaseMigration
{
    public long Version => 2026072002;
    public string Name => "codegate_git_push_traceability";
    public string Sql => """
        CREATE TABLE codegate_git_pushes (
            audit_id TEXT PRIMARY KEY,
            observed_at TEXT NOT NULL,
            actor TEXT NOT NULL,
            repository_path TEXT NOT NULL,
            repository_name TEXT NOT NULL,
            ref_name TEXT NOT NULL,
            branch TEXT NOT NULL,
            old_revision TEXT NOT NULL,
            new_revision TEXT NOT NULL,
            submission_id TEXT NOT NULL,
            verdict TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            FOREIGN KEY(submission_id) REFERENCES codegate_submissions(submission_id)
                ON DELETE CASCADE
        );
        CREATE INDEX ix_codegate_git_pushes_seen
            ON codegate_git_pushes(observed_at DESC);
        CREATE INDEX ix_codegate_git_pushes_repo_branch
            ON codegate_git_pushes(repository_name, branch, observed_at DESC);
        CREATE INDEX ix_codegate_git_pushes_verdict
            ON codegate_git_pushes(verdict, risk_score DESC);

        CREATE TABLE codegate_git_push_files (
            audit_id TEXT NOT NULL,
            file_path TEXT NOT NULL,
            ordinal INTEGER NOT NULL,
            PRIMARY KEY(audit_id, file_path),
            FOREIGN KEY(audit_id) REFERENCES codegate_git_pushes(audit_id)
                ON DELETE CASCADE
        );
        CREATE INDEX ix_codegate_git_push_files_audit
            ON codegate_git_push_files(audit_id, ordinal);
        """;
}
