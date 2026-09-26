using System.Text.Json;
using Microsoft.Data.Sqlite;
using RoamSentinel.Core;

namespace RoamSentinel.Database;

public sealed class AgentRegistryRepository(
    IDatabaseConnectionFactory connections) : IAgentRegistryRepository
{
    public IReadOnlyList<AgentDefinitionDto> GetDefinitions()
    {
        using var connection = connections.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT agent_key, display_name, vendor, identity_markers_json,
                   trusted_path_markers_json, shared_host
            FROM agent_catalog
            WHERE enabled = 1
            ORDER BY display_name;
            """;
        using var reader = command.ExecuteReader();
        var definitions = new List<AgentDefinitionDto>();
        while (reader.Read())
        {
            definitions.Add(new AgentDefinitionDto(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                DeserializeArray(reader.GetString(3)),
                DeserializeArray(reader.GetString(4)),
                reader.GetInt32(5) == 1));
        }

        return definitions;
    }

    public void UpsertObservations(
        IReadOnlyCollection<AgentGovernanceDto> agents,
        DateTimeOffset observedAt)
    {
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        foreach (var agent in agents)
        {
            var changed = HasMeaningfulChange(
                connection,
                transaction,
                agent);
            Upsert(connection, transaction, agent);
            if (changed)
            {
                RecordActivity(connection, transaction, agent, observedAt);
            }
        }
        MarkMissingAgentsStopped(connection, transaction, agents);

        AuditSql.Insert(
            connection,
            transaction,
            "system",
            "agent_governance.observed",
            "agent_registry",
            "*",
            true,
            JsonSerializer.Serialize(new
            {
                ObservedAt = observedAt,
                Count = agents.Count,
                CriticalCount = agents.Count(item => item.RiskScore >= 90),
                NetworkActiveCount = agents.Count(
                    item => item.NetworkConnectionCount > 0)
            }));
        transaction.Commit();
    }

    public IReadOnlyList<AgentGovernanceDto> GetAll()
    {
        using var connection = connections.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT agent_key, display_name, executable_path, publisher,
                   trust_state, first_seen_at, last_seen_at, is_running,
                   process_id, network_connection_count,
                   distinct_remote_address_count, network_last_seen,
                   risk_score, risk_reason, network_authorized,
                   can_enforce_path
            FROM agent_registry
            ORDER BY risk_score DESC, last_seen_at DESC, display_name;
            """;
        using var reader = command.ExecuteReader();
        var agents = new List<AgentGovernanceDto>();
        while (reader.Read())
        {
            agents.Add(new AgentGovernanceDto(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetString(4),
                DateTimeOffset.Parse(reader.GetString(5)),
                DateTimeOffset.Parse(reader.GetString(6)),
                reader.GetInt32(7) == 1,
                reader.IsDBNull(8) ? null : reader.GetInt32(8),
                reader.GetInt32(9),
                reader.GetInt32(10),
                reader.IsDBNull(11)
                    ? null
                    : DateTimeOffset.Parse(reader.GetString(11)),
                reader.GetInt32(12),
                reader.GetString(13),
                reader.GetInt32(14) == 1,
                reader.GetInt32(15) == 1));
        }

        return agents;
    }

    private static void Upsert(
        SqliteConnection connection,
        SqliteTransaction transaction,
        AgentGovernanceDto agent)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO agent_registry (
                executable_path, display_name, trust_state, publisher,
                first_seen_at, last_seen_at, agent_key, is_running,
                process_id, network_connection_count,
                distinct_remote_address_count, network_last_seen,
                risk_score, risk_reason, network_authorized,
                can_enforce_path
            ) VALUES (
                $path, $name, $status, $vendor,
                $firstSeen, $lastSeen, $agentKey, $isRunning,
                $processId, $connectionCount,
                $remoteCount, $networkLastSeen,
                $riskScore, $riskReason, $networkAuthorized,
                $canEnforcePath
            )
            ON CONFLICT(executable_path) DO UPDATE SET
                display_name = excluded.display_name,
                publisher = excluded.publisher,
                last_seen_at = excluded.last_seen_at,
                agent_key = excluded.agent_key,
                is_running = excluded.is_running,
                process_id = excluded.process_id,
                network_connection_count = excluded.network_connection_count,
                distinct_remote_address_count =
                    excluded.distinct_remote_address_count,
                network_last_seen = excluded.network_last_seen,
                risk_score = excluded.risk_score,
                risk_reason = excluded.risk_reason,
                can_enforce_path = excluded.can_enforce_path,
                trust_state = CASE
                    WHEN agent_registry.trust_state = 'blocked' THEN 'blocked'
                    WHEN agent_registry.network_authorized = 1 THEN 'trusted'
                    ELSE excluded.trust_state
                END,
                network_authorized = agent_registry.network_authorized;
            """;
        command.Parameters.AddWithValue("$path", agent.ExecutablePath);
        command.Parameters.AddWithValue("$name", agent.Name);
        command.Parameters.AddWithValue("$status", agent.Status);
        command.Parameters.AddWithValue("$vendor", agent.Vendor);
        command.Parameters.AddWithValue(
            "$firstSeen",
            agent.FirstSeen.ToUniversalTime().ToString("O"));
        command.Parameters.AddWithValue(
            "$lastSeen",
            agent.LastSeen.ToUniversalTime().ToString("O"));
        command.Parameters.AddWithValue("$agentKey", agent.AgentKey);
        command.Parameters.AddWithValue("$isRunning", agent.IsRunning ? 1 : 0);
        command.Parameters.AddWithValue(
            "$processId",
            agent.ProcessId is null ? DBNull.Value : agent.ProcessId.Value);
        command.Parameters.AddWithValue(
            "$connectionCount",
            agent.NetworkConnectionCount);
        command.Parameters.AddWithValue(
            "$remoteCount",
            agent.DistinctRemoteAddressCount);
        command.Parameters.AddWithValue(
            "$networkLastSeen",
            agent.NetworkLastSeen is null
                ? DBNull.Value
                : agent.NetworkLastSeen.Value.ToUniversalTime().ToString("O"));
        command.Parameters.AddWithValue("$riskScore", agent.RiskScore);
        command.Parameters.AddWithValue("$riskReason", agent.RiskReason);
        command.Parameters.AddWithValue(
            "$networkAuthorized",
            agent.NetworkAuthorized ? 1 : 0);
        command.Parameters.AddWithValue(
            "$canEnforcePath",
            agent.CanEnforcePath ? 1 : 0);
        command.ExecuteNonQuery();
    }

    private static bool HasMeaningfulChange(
        SqliteConnection connection,
        SqliteTransaction transaction,
        AgentGovernanceDto agent)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT trust_state, is_running, network_connection_count,
                   distinct_remote_address_count, risk_score,
                   network_authorized
            FROM agent_registry
            WHERE executable_path = $path;
            """;
        command.Parameters.AddWithValue("$path", agent.ExecutablePath);
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return true;
        }

        return !string.Equals(
                   reader.GetString(0),
                   agent.Status,
                   StringComparison.OrdinalIgnoreCase) ||
               reader.GetInt32(1) != (agent.IsRunning ? 1 : 0) ||
               reader.GetInt32(2) != agent.NetworkConnectionCount ||
               reader.GetInt32(3) != agent.DistinctRemoteAddressCount ||
               reader.GetInt32(4) != agent.RiskScore ||
               reader.GetInt32(5) != (agent.NetworkAuthorized ? 1 : 0);
    }

    private static void RecordActivity(
        SqliteConnection connection,
        SqliteTransaction transaction,
        AgentGovernanceDto agent,
        DateTimeOffset observedAt)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO agent_activity (
                agent_id, executable_path, occurred_at, activity_type,
                detail_json
            ) VALUES (
                (SELECT agent_id FROM agent_registry
                 WHERE executable_path = $path),
                $path, $occurredAt, 'observation', $detailJson
            );
            """;
        command.Parameters.AddWithValue("$path", agent.ExecutablePath);
        command.Parameters.AddWithValue(
            "$occurredAt",
            observedAt.ToUniversalTime().ToString("O"));
        command.Parameters.AddWithValue(
            "$detailJson",
            JsonSerializer.Serialize(new
            {
                agent.Name,
                agent.Vendor,
                agent.Status,
                agent.IsRunning,
                agent.ProcessId,
                agent.NetworkConnectionCount,
                agent.DistinctRemoteAddressCount,
                agent.RiskScore,
                agent.RiskReason
            }));
        command.ExecuteNonQuery();
    }

    private static void MarkMissingAgentsStopped(
        SqliteConnection connection,
        SqliteTransaction transaction,
        IReadOnlyCollection<AgentGovernanceDto> agents)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        var pathParameters = agents
            .Select((agent, index) => new
            {
                Name = $"$path{index}",
                agent.ExecutablePath
            })
            .ToList();
        var exclusion = pathParameters.Count == 0
            ? ""
            : $" AND executable_path NOT IN ({string.Join(
                ", ",
                pathParameters.Select(item => item.Name))})";
        command.CommandText = $"""
            UPDATE agent_registry
            SET is_running = 0,
                process_id = NULL,
                network_connection_count = 0,
                distinct_remote_address_count = 0
            WHERE is_running = 1{exclusion};
            """;
        foreach (var parameter in pathParameters)
        {
            command.Parameters.AddWithValue(
                parameter.Name,
                parameter.ExecutablePath);
        }

        command.ExecuteNonQuery();
    }

    private static IReadOnlyList<string> DeserializeArray(string json) =>
        JsonSerializer.Deserialize<string[]>(json) ?? [];
}
