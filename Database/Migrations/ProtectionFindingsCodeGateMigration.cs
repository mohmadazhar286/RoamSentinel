namespace RoamSentinel.Database.Migrations;

public sealed class ProtectionFindingsCodeGateMigration : IDatabaseMigration
{
    public long Version => 2026072001;
    public string Name => "device_integrity_findings_and_codegate_audit";
    public string Sql => """
        CREATE TABLE device_integrity_findings (
            finding_id TEXT PRIMARY KEY,
            source_event_id TEXT NOT NULL UNIQUE,
            observed_at TEXT NOT NULL,
            severity TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            entity_type TEXT NOT NULL,
            entity_key TEXT NOT NULL,
            change_type TEXT NOT NULL,
            title TEXT NOT NULL,
            explanation TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open' CHECK (
                status IN ('open', 'expected', 'suppressed', 'resolved')),
            resolution_note TEXT NOT NULL DEFAULT '',
            resolved_at TEXT NULL,
            resolved_by TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(source_event_id) REFERENCES device_integrity_events(event_id)
                ON DELETE CASCADE
        );
        CREATE INDEX ix_device_integrity_findings_status
            ON device_integrity_findings(status, risk_score DESC, observed_at DESC);
        CREATE INDEX ix_device_integrity_findings_entity
            ON device_integrity_findings(entity_type, entity_key);

        CREATE TABLE codegate_submissions (
            submission_id TEXT PRIMARY KEY,
            evaluated_at TEXT NOT NULL,
            actor TEXT NOT NULL,
            source TEXT NOT NULL,
            revision TEXT NOT NULL,
            import_path TEXT NOT NULL,
            verdict TEXT NOT NULL CHECK (
                verdict IN ('allow', 'warn', 'block', 'needs_review', 'not_evaluated')),
            risk_score INTEGER NOT NULL,
            file_count INTEGER NOT NULL,
            content_sha256 TEXT NOT NULL
        );
        CREATE INDEX ix_codegate_submissions_seen
            ON codegate_submissions(evaluated_at DESC);
        CREATE INDEX ix_codegate_submissions_verdict
            ON codegate_submissions(verdict, risk_score DESC);

        CREATE TABLE codegate_findings (
            finding_id TEXT PRIMARY KEY,
            submission_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            file_path TEXT NOT NULL,
            evidence TEXT NOT NULL,
            explanation TEXT NOT NULL,
            FOREIGN KEY(submission_id) REFERENCES codegate_submissions(submission_id)
                ON DELETE CASCADE
        );
        CREATE INDEX ix_codegate_findings_submission
            ON codegate_findings(submission_id);
        CREATE INDEX ix_codegate_findings_rule
            ON codegate_findings(rule_id, severity);
        """;
}
