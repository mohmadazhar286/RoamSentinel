using System.Text.Json;
using RoamSentinel.Core;

namespace RoamSentinel.Database;

public sealed class DetectionRuleRepository(
    IDatabaseConnectionFactory connections) : IDetectionRuleRepository
{
    public IReadOnlyList<DetectionRuleDto> GetAll()
    {
        using var connection = connections.OpenConnection();
        var mappings = ReadMappings(connection);
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT rule_id, name, description, category, enabled, severity,
                   risk_weight, confidence, configuration_json
            FROM detection_rules
            ORDER BY category, name;
            """;
        using var reader = command.ExecuteReader();
        var rules = new List<DetectionRuleDto>();
        while (reader.Read())
        {
            var ruleId = reader.GetString(0);
            rules.Add(new DetectionRuleDto(
                ruleId,
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetInt64(4) != 0,
                reader.GetString(5),
                reader.GetInt32(6),
                reader.GetInt32(7),
                reader.GetString(8),
                mappings.GetValueOrDefault(ruleId) ?? []));
        }

        return rules;
    }

    public DetectionRuleDto? SetEnabled(string ruleId, bool enabled)
    {
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE detection_rules
            SET enabled = $enabled, updated_at = $updatedAt
            WHERE rule_id = $ruleId;
            """;
        command.Parameters.AddWithValue("$enabled", enabled ? 1 : 0);
        command.Parameters.AddWithValue(
            "$updatedAt",
            DateTimeOffset.UtcNow.ToString("O"));
        command.Parameters.AddWithValue("$ruleId", ruleId);
        var changed = command.ExecuteNonQuery();
        AuditSql.Insert(
            connection,
            transaction,
            "local-user",
            "detection_rule.enabled_changed",
            "detection_rule",
            ruleId,
            changed > 0,
            JsonSerializer.Serialize(new { Enabled = enabled }));
        transaction.Commit();
        return changed > 0
            ? GetAll().First(rule => rule.RuleId == ruleId)
            : null;
    }

    private static Dictionary<string, IReadOnlyList<MitreMappingDto>>
        ReadMappings(Microsoft.Data.Sqlite.SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT rule_id, tactic, technique_id, technique_name,
                   subtechnique_id, mapping_type
            FROM mitre_mappings
            ORDER BY rule_id, tactic, technique_id;
            """;
        using var reader = command.ExecuteReader();
        var mappings = new Dictionary<string, List<MitreMappingDto>>(
            StringComparer.OrdinalIgnoreCase);
        while (reader.Read())
        {
            var ruleId = reader.GetString(0);
            if (!mappings.TryGetValue(ruleId, out var items))
            {
                items = [];
                mappings[ruleId] = items;
            }

            items.Add(new MitreMappingDto(
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.IsDBNull(4) ? null : reader.GetString(4),
                reader.GetString(5)));
        }

        return mappings.ToDictionary(
            item => item.Key,
            item => (IReadOnlyList<MitreMappingDto>)item.Value,
            StringComparer.OrdinalIgnoreCase);
    }
}
