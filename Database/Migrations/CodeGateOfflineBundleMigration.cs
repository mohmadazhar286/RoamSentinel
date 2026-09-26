namespace RoamSentinel.Database.Migrations;

public sealed class CodeGateOfflineBundleMigration : IDatabaseMigration
{
    public long Version => 2026072003;
    public string Name => "codegate_offline_bundle_imports";
    public string Sql => """
        CREATE TABLE codegate_offline_bundles (
            bundle_id TEXT PRIMARY KEY,
            imported_at TEXT NOT NULL,
            component TEXT NOT NULL,
            bundle_type TEXT NOT NULL,
            name TEXT NOT NULL,
            version TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            generated_at TEXT NOT NULL,
            source TEXT NOT NULL,
            sha256 TEXT NOT NULL UNIQUE,
            signature TEXT NOT NULL,
            verified INTEGER NOT NULL,
            status TEXT NOT NULL,
            message TEXT NOT NULL,
            imported_by TEXT NOT NULL
        );
        CREATE INDEX ix_codegate_offline_bundles_type
            ON codegate_offline_bundles(bundle_type, imported_at DESC);
        CREATE INDEX ix_codegate_offline_bundles_component
            ON codegate_offline_bundles(component, imported_at DESC);
        """;
}
