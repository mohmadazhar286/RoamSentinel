using System.Text.Json;
using Microsoft.Data.Sqlite;
using RoamSentinel.Core;

namespace RoamSentinel.Database;

public sealed class AgentPolicyRepository(
    IDatabaseConnectionFactory connections) : IAgentPolicyRepository
{
    public AgentPolicy Load()
    {
        using var connection = connections.OpenConnection();
        return Load(connection, transaction: null);
    }

    public AgentPolicy Save(AgentPolicy policy)
    {
        var normalized = new AgentPolicy(
            policy.AuthorizedPaths,
            policy.BlockedPaths);

        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        var previous = Load(connection, transaction);
        var now = DateTimeOffset.UtcNow.ToString("O");

        foreach (var path in normalized.AuthorizedPaths)
        {
            UpsertAgent(
                connection,
                transaction,
                path,
                "trusted",
                networkAuthorized: true,
                now);
        }

        foreach (var path in normalized.BlockedPaths)
        {
            UpsertAgent(
                connection,
                transaction,
                path,
                "blocked",
                networkAuthorized: false,
                now);
        }

        var removedPaths = previous.AuthorizedPaths
            .Concat(previous.BlockedPaths)
            .Except(
                normalized.AuthorizedPaths.Concat(normalized.BlockedPaths),
                StringComparer.OrdinalIgnoreCase)
            .ToList();
        foreach (var path in removedPaths)
        {
            using var remove = connection.CreateCommand();
            remove.Transaction = transaction;
            remove.CommandText = """
                UPDATE agent_registry
                SET trust_state = 'unknown',
                    network_authorized = 0,
                    last_seen_at = $now
                WHERE executable_path = $path;
                """;
            remove.Parameters.AddWithValue("$path", path);
            remove.Parameters.AddWithValue("$now", now);
            remove.ExecuteNonQuery();
            RecordActivity(
                connection,
                transaction,
                path,
                "trust_removed",
                now);
        }

        var changes = GetChanges(previous, normalized);
        foreach (var change in changes)
        {
            RecordActivity(
                connection,
                transaction,
                change.Path,
                change.State,
                now);
        }

        AuditSql.Insert(
            connection,
            transaction,
            "local-user",
            "agent_policy.saved",
            "agent_registry",
            "*",
            true,
            JsonSerializer.Serialize(new
            {
                AuthorizedCount = normalized.AuthorizedPaths.Count,
                BlockedCount = normalized.BlockedPaths.Count,
                ChangedPaths = changes.Select(change => change.Path)
            }));
        transaction.Commit();
        return normalized;
    }

    private static AgentPolicy Load(
        SqliteConnection connection,
        SqliteTransaction? transaction)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT executable_path, trust_state, network_authorized
            FROM agent_registry
            WHERE network_authorized = 1 OR trust_state = 'blocked';
            """;

        using var reader = command.ExecuteReader();
        var authorized = new List<string>();
        var blocked = new List<string>();
        while (reader.Read())
        {
            var path = reader.GetString(0);
            if (reader.GetInt32(2) == 1)
            {
                authorized.Add(path);
            }
            else
            {
                blocked.Add(path);
            }
        }

        return new AgentPolicy(authorized, blocked);
    }

    private static void UpsertAgent(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string path,
        string state,
        bool networkAuthorized,
        string now)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO agent_registry (
                executable_path, trust_state, first_seen_at, last_seen_at,
                network_authorized
            ) VALUES (
                $path, $state, $now, $now, $networkAuthorized
            )
            ON CONFLICT(executable_path) DO UPDATE SET
                trust_state = excluded.trust_state,
                network_authorized = excluded.network_authorized,
                last_seen_at = excluded.last_seen_at;
            """;
        command.Parameters.AddWithValue("$path", path);
        command.Parameters.AddWithValue("$state", state);
        command.Parameters.AddWithValue(
            "$networkAuthorized",
            networkAuthorized ? 1 : 0);
        command.Parameters.AddWithValue("$now", now);
        command.ExecuteNonQuery();
    }

    private static void RecordActivity(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string path,
        string activityType,
        string now)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO agent_activity (
                agent_id, executable_path, occurred_at, activity_type, detail_json
            ) VALUES (
                (SELECT agent_id FROM agent_registry WHERE executable_path = $path),
                $path, $occurredAt, $activityType, '{}'
            );
            """;
        command.Parameters.AddWithValue("$path", path);
        command.Parameters.AddWithValue("$occurredAt", now);
        command.Parameters.AddWithValue("$activityType", activityType);
        command.ExecuteNonQuery();
    }

    private static IReadOnlyList<(string Path, string State)> GetChanges(
        AgentPolicy previous,
        AgentPolicy current)
    {
        var changes = new List<(string Path, string State)>();
        changes.AddRange(current.AuthorizedPaths
            .Where(path => !previous.AuthorizedPaths.Contains(path))
            .Select(path => (path, "authorized")));
        changes.AddRange(current.BlockedPaths
            .Where(path => !previous.BlockedPaths.Contains(path))
            .Select(path => (path, "blocked")));
        return changes;
    }
}
