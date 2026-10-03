using System.Text.Json;
using RoamSentinel.Core;

namespace RoamSentinel.Database;

public sealed class CodeGateActiveRuleRepository(
    IDatabaseConnectionFactory connections) : ICodeGateActiveRuleRepository
{
    public IReadOnlyList<CodeGateActiveRuleDto> GetActiveRules()
    {
        using var connection = connections.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT rule_id, bundle_id, name, severity, risk_score,
                   pattern, explanation, enabled
            FROM codegate_active_rules
            WHERE enabled = 1
            ORDER BY risk_score DESC, rule_id;
            """;
        using var reader = command.ExecuteReader();
        var rules = new List<CodeGateActiveRuleDto>();
        while (reader.Read())
        {
            rules.Add(new CodeGateActiveRuleDto(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetInt32(4),
                reader.GetString(5),
                reader.GetString(6),
                reader.GetInt32(7) != 0));
        }

        return rules;
    }

    public void SaveRules(string bundleId, IReadOnlyList<CodeGateActiveRuleDto> rules)
    {
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        using var delete = connection.CreateCommand();
        delete.Transaction = transaction;
        delete.CommandText = "DELETE FROM codegate_active_rules WHERE bundle_id = $bundleId;";
        delete.Parameters.AddWithValue("$bundleId", bundleId);
        delete.ExecuteNonQuery();

        foreach (var rule in rules)
        {
            using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO codegate_active_rules (
                    rule_id, bundle_id, name, severity, risk_score,
                    pattern, explanation, enabled, created_at
                ) VALUES (
                    $ruleId, $bundleId, $name, $severity, $riskScore,
                    $pattern, $explanation, $enabled, $createdAt
                )
                ON CONFLICT(rule_id) DO UPDATE SET
                    bundle_id = excluded.bundle_id,
                    name = excluded.name,
                    severity = excluded.severity,
                    risk_score = excluded.risk_score,
                    pattern = excluded.pattern,
                    explanation = excluded.explanation,
                    enabled = excluded.enabled,
                    created_at = excluded.created_at;
                """;
            insert.Parameters.AddWithValue("$ruleId", rule.RuleId);
            insert.Parameters.AddWithValue("$bundleId", bundleId);
            insert.Parameters.AddWithValue("$name", rule.Name);
            insert.Parameters.AddWithValue("$severity", rule.Severity);
            insert.Parameters.AddWithValue("$riskScore", rule.RiskScore);
            insert.Parameters.AddWithValue("$pattern", rule.Pattern);
            insert.Parameters.AddWithValue("$explanation", rule.Explanation);
            insert.Parameters.AddWithValue("$enabled", rule.Enabled ? 1 : 0);
            insert.Parameters.AddWithValue(
                "$createdAt",
                DateTimeOffset.UtcNow.ToString("O"));
            insert.ExecuteNonQuery();
        }

        AuditSql.Insert(
            connection,
            transaction,
            "Administrator",
            "codegate.active_rules_saved",
            "codegate_active_rule",
            bundleId,
            true,
            JsonSerializer.Serialize(new
            {
                BundleId = bundleId,
                RuleCount = rules.Count
            }));
        transaction.Commit();
    }

    public void DeleteRulesByBundle(string bundleId)
    {
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "DELETE FROM codegate_active_rules WHERE bundle_id = $bundleId;";
        command.Parameters.AddWithValue("$bundleId", bundleId);
        var rows = command.ExecuteNonQuery();
        if (rows > 0)
        {
            AuditSql.Insert(
                connection,
                transaction,
                "Administrator",
                "codegate.active_rules_deleted",
                "codegate_active_rule",
                bundleId,
                true,
                JsonSerializer.Serialize(new { BundleId = bundleId, DeletedCount = rows }));
        }

        transaction.Commit();
    }
}
