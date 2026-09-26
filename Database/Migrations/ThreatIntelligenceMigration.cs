namespace RoamSentinel.Database.Migrations;

public sealed class ThreatIntelligenceMigration : IDatabaseMigration
{
    public long Version => 2026070406;
    public string Name => "threat_intelligence_enrichment";

    public string Sql => """
        ALTER TABLE threat_indicators
            ADD COLUMN description TEXT NOT NULL DEFAULT '';
        ALTER TABLE threat_indicators
            ADD COLUMN tags_json TEXT NOT NULL DEFAULT '[]';
        ALTER TABLE threat_indicators
            ADD COLUMN updated_at TEXT NOT NULL DEFAULT '';

        CREATE INDEX IF NOT EXISTS ix_threat_indicators_type_reputation
            ON threat_indicators(indicator_type, reputation, expires_at);
        CREATE INDEX IF NOT EXISTS ix_threat_indicators_source_updated
            ON threat_indicators(source, updated_at DESC);
        """;
}
