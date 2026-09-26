using System.Text.Json;
using Microsoft.Data.Sqlite;
using RoamSentinel.Config;
using RoamSentinel.Core;

namespace RoamSentinel.Database;

public interface ILegacyDataImporter
{
    void Import();
}

public sealed class LegacyDataImporter(
    IDatabaseConnectionFactory connections,
    DatabaseOptions options) : ILegacyDataImporter
{
    private const string ImportSetting = "legacy_json_import.completed";

    public void Import()
    {
        if (!options.ImportLegacyJson)
        {
            return;
        }

        using var connection = connections.OpenConnection();
        if (HasCompleted(connection))
        {
            return;
        }

        var directory = Path.GetDirectoryName(connections.DatabasePath)!;
        using var transaction = connection.BeginTransaction();
        var eventCount = ImportEvents(
            connection,
            transaction,
            Path.Combine(directory, "events.jsonl"));
        var agentCount = ImportAgentPolicy(
            connection,
            transaction,
            Path.Combine(directory, "agent-policy.json"));
        var ipCount = ImportIpBlocks(
            connection,
            transaction,
            Path.Combine(directory, "ip-blocks.json"));

        using var setting = connection.CreateCommand();
        setting.Transaction = transaction;
        setting.CommandText = """
            INSERT INTO system_settings (
                setting_key, setting_value, value_type, updated_at
            ) VALUES (
                $key, 'true', 'boolean', $updatedAt
            )
            ON CONFLICT(setting_key) DO UPDATE SET
                setting_value = excluded.setting_value,
                value_type = excluded.value_type,
                updated_at = excluded.updated_at;
            """;
        setting.Parameters.AddWithValue("$key", ImportSetting);
        setting.Parameters.AddWithValue(
            "$updatedAt",
            DateTimeOffset.UtcNow.ToString("O"));
        setting.ExecuteNonQuery();

        AuditSql.Insert(
            connection,
            transaction,
            "system",
            "legacy_json.imported",
            "database",
            connections.DatabasePath,
            true,
            JsonSerializer.Serialize(new
            {
                SecurityEvents = eventCount,
                AgentPolicies = agentCount,
                IpBlocks = ipCount
            }));
        transaction.Commit();
    }

    private static bool HasCompleted(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT setting_value
            FROM system_settings
            WHERE setting_key = $key;
            """;
        command.Parameters.AddWithValue("$key", ImportSetting);
        return string.Equals(
            command.ExecuteScalar()?.ToString(),
            "true",
            StringComparison.OrdinalIgnoreCase);
    }

    private static int ImportEvents(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string path)
    {
        if (!File.Exists(path))
        {
            return 0;
        }

        var count = 0;
        foreach (var line in File.ReadLines(path))
        {
            try
            {
                var alert = JsonSerializer.Deserialize<AlertDto>(line);
                if (alert is null)
                {
                    continue;
                }

                using var command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText = """
                    INSERT OR IGNORE INTO security_events (
                        event_id, occurred_at, last_seen_at, category, severity,
                        title, detail, occurrence_count
                    ) VALUES (
                        $id, $occurredAt, $lastSeenAt, $category, $severity,
                        $title, $detail, 1
                    );
                    """;
                command.Parameters.AddWithValue("$id", alert.Id);
                command.Parameters.AddWithValue(
                    "$occurredAt",
                    alert.Timestamp.ToUniversalTime().ToString("O"));
                command.Parameters.AddWithValue(
                    "$lastSeenAt",
                    alert.Timestamp.ToUniversalTime().ToString("O"));
                command.Parameters.AddWithValue("$category", alert.Category);
                command.Parameters.AddWithValue("$severity", alert.Severity);
                command.Parameters.AddWithValue("$title", alert.Title);
                command.Parameters.AddWithValue("$detail", alert.Detail);
                count += command.ExecuteNonQuery();
            }
            catch
            {
                // Preserve valid legacy lines if one line is malformed.
            }
        }

        return count;
    }

    private static int ImportAgentPolicy(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string path)
    {
        var policy = JsonFileStore.Load(path, () => new AgentPolicy());
        var count = 0;
        var now = DateTimeOffset.UtcNow.ToString("O");
        foreach (var item in policy.AuthorizedPaths
            .Select(pathValue => (Path: pathValue, State: "authorized"))
            .Concat(policy.BlockedPaths.Select(
                pathValue => (Path: pathValue, State: "blocked"))))
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT OR IGNORE INTO agent_registry (
                    executable_path, trust_state, first_seen_at, last_seen_at
                ) VALUES ($path, $state, $now, $now);
                """;
            command.Parameters.AddWithValue("$path", item.Path);
            command.Parameters.AddWithValue("$state", item.State);
            command.Parameters.AddWithValue("$now", now);
            count += command.ExecuteNonQuery();
        }

        return count;
    }

    private static int ImportIpBlocks(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string path)
    {
        var blocks = JsonFileStore.Load(
            path,
            () => new List<IpBlockDto>());
        var count = 0;
        foreach (var block in blocks)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT OR IGNORE INTO ip_blocks (
                    ip_address, display_name, blocked_at
                ) VALUES ($ipAddress, $displayName, $blockedAt);
                """;
            command.Parameters.AddWithValue("$ipAddress", block.IpAddress);
            command.Parameters.AddWithValue("$displayName", block.DisplayName);
            command.Parameters.AddWithValue(
                "$blockedAt",
                block.BlockedAt.ToUniversalTime().ToString("O"));
            count += command.ExecuteNonQuery();
        }

        return count;
    }
}
