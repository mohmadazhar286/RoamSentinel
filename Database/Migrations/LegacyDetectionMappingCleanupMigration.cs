namespace RoamSentinel.Database.Migrations;

public sealed class LegacyDetectionMappingCleanupMigration : IDatabaseMigration
{
    public long Version => 2026070404;
    public string Name => "remove_legacy_detection_mapping";

    public string Sql => """
        DELETE FROM mitre_mappings
        WHERE rule_id = 'RS-NET-001';
        """;
}
