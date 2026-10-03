using System.Text.Json;
using RoamSentinel.Core;

namespace RoamSentinel.Database;

public sealed class AgentEgressRuleRepository(
    IDatabaseConnectionFactory connections) : IAgentEgressRuleRepository
{
    public IReadOnlyList<AgentEgressRuleDto> GetAll()
    {
        using var connection = connections.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT rule_id, agent_key, executable_path, display_name,
                   direction, action, created_at, created_by
            FROM agent_egress_rules
            ORDER BY created_at DESC;
            """;
        using var reader = command.ExecuteReader();
        var rules = new List<AgentEgressRuleDto>();
        while (reader.Read())
        {
            rules.Add(new AgentEgressRuleDto(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetString(4),
                reader.GetString(5),
                DateTimeOffset.Parse(reader.GetString(6)),
                reader.GetString(7)));
        }

        return rules;
    }

    public AgentEgressRuleDto? FindByPath(string executablePath)
    {
        using var connection = connections.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT rule_id, agent_key, executable_path, display_name,
                   direction, action, created_at, created_by
            FROM agent_egress_rules
            WHERE executable_path = $path;
            """;
        command.Parameters.AddWithValue("$path", executablePath);
        using var reader = command.ExecuteReader();
        return reader.Read()
            ? new AgentEgressRuleDto(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetString(4),
                reader.GetString(5),
                DateTimeOffset.Parse(reader.GetString(6)),
                reader.GetString(7))
            : null;
    }

    public void Upsert(AgentEgressRuleDto rule)
    {
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO agent_egress_rules (
                rule_id, agent_key, executable_path, display_name,
                direction, action, created_at, created_by
            ) VALUES (
                $ruleId, $agentKey, $path, $displayName,
                $direction, $action, $createdAt, $createdBy
            )
            ON CONFLICT(executable_path) DO UPDATE SET
                rule_id = excluded.rule_id,
                agent_key = excluded.agent_key,
                display_name = excluded.display_name,
                direction = excluded.direction,
                action = excluded.action,
                created_at = excluded.created_at,
                created_by = excluded.created_by;
            """;
        command.Parameters.AddWithValue("$ruleId", rule.RuleId);
        command.Parameters.AddWithValue("$agentKey", rule.AgentKey);
        command.Parameters.AddWithValue("$path", rule.ExecutablePath);
        command.Parameters.AddWithValue("$displayName", rule.DisplayName);
        command.Parameters.AddWithValue("$direction", rule.Direction);
        command.Parameters.AddWithValue("$action", rule.Action);
        command.Parameters.AddWithValue(
            "$createdAt",
            rule.CreatedAt.ToUniversalTime().ToString("O"));
        command.Parameters.AddWithValue("$createdBy", rule.CreatedBy);
        command.ExecuteNonQuery();

        AuditSql.Insert(
            connection,
            transaction,
            rule.CreatedBy,
            "agent_egress.rule_upserted",
            "agent_egress_rule",
            rule.ExecutablePath,
            true,
            JsonSerializer.Serialize(new
            {
                rule.RuleId,
                rule.AgentKey,
                rule.DisplayName,
                rule.Action,
                rule.Direction
            }));
        transaction.Commit();
    }

    public bool Remove(string executablePath)
    {
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            DELETE FROM agent_egress_rules
            WHERE executable_path = $path;
            """;
        command.Parameters.AddWithValue("$path", executablePath);
        var rows = command.ExecuteNonQuery();
        if (rows > 0)
        {
            AuditSql.Insert(
                connection,
                transaction,
                "Administrator",
                "agent_egress.rule_removed",
                "agent_egress_rule",
                executablePath,
                true,
                JsonSerializer.Serialize(new { Path = executablePath }));
        }

        transaction.Commit();
        return rows > 0;
    }
}
