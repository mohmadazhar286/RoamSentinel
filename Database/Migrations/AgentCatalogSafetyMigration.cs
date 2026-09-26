namespace RoamSentinel.Database.Migrations;

public sealed class AgentCatalogSafetyMigration : IDatabaseMigration
{
    public long Version => 2026070409;
    public string Name => "agent_catalog_path_safety";

    public string Sql => """
        UPDATE agent_catalog
        SET trusted_path_markers_json =
                '["\\appdata\\roaming\\npm\\codex","\\appdata\\local\\openai\\codex","\\program files\\windowsapps\\openai.codex_"]',
            shared_host = 0
        WHERE agent_key = 'codex';

        UPDATE agent_catalog
        SET shared_host = 0
        WHERE agent_key IN ('aider', 'openhands');
        """;
}
