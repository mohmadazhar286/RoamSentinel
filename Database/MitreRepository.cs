using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using RoamSentinel.Config;
using RoamSentinel.Core;

namespace RoamSentinel.Database;

public sealed class MitreRepository(
    IDatabaseConnectionFactory connections,
    DetectionOptions options) : IMitreRepository
{
    private readonly Lock _gate = new();
    private string _lastSignature = "";
    private DateTimeOffset _lastPersisted = DateTimeOffset.MinValue;

    public bool PersistFindings(DetectionResultDto result, string host)
    {
        var signature = BuildSignature(result.Findings);
        lock (_gate)
        {
            if (signature == _lastSignature &&
                result.ObservedAt - _lastPersisted <
                    TimeSpan.FromSeconds(
                        options.FindingPersistenceIntervalSeconds))
            {
                return false;
            }

            using var connection = connections.OpenConnection();
            using var transaction = connection.BeginTransaction();
            foreach (var finding in result.Findings)
            {
                UpsertFinding(connection, transaction, finding, host);
            }

            AuditSql.Insert(
                connection,
                transaction,
                "system",
                "detection.findings.persisted",
                "detection_snapshot",
                result.ObservedAt.ToUniversalTime().ToString("O"),
                true,
                JsonSerializer.Serialize(new
                {
                    Host = host,
                    FindingCount = result.Findings.Count,
                    result.OverallRiskScore,
                    result.OverallSeverity
                }));
            transaction.Commit();
            _lastSignature = signature;
            _lastPersisted = result.ObservedAt;
            return true;
        }
    }

    public IReadOnlyList<MitreTechniqueDto> GetTechniques()
    {
        using var connection = connections.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT technique_id, name, primary_tactic, status, replaced_by, url
            FROM mitre_techniques
            ORDER BY primary_tactic, technique_id;
            """;
        using var reader = command.ExecuteReader();
        var techniques = new List<MitreTechniqueDto>();
        while (reader.Read())
        {
            techniques.Add(new MitreTechniqueDto(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.IsDBNull(4) ? null : reader.GetString(4),
                reader.GetString(5)));
        }

        return techniques;
    }

    public IReadOnlyList<MitreEventDto> GetEvents(int limit)
    {
        using var connection = connections.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT f.finding_id, f.rule_id, m.tactic, m.technique_id,
                   m.technique_name, m.mapping_type, f.severity, f.host,
                   f.first_seen_at, f.last_seen_at, f.occurrence_count,
                   f.category, f.title, f.evidence, f.entity_type, f.entity_id
            FROM detection_findings f
            INNER JOIN mitre_mappings m ON m.rule_id = f.rule_id
            ORDER BY f.last_seen_at DESC, f.severity, m.technique_id
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 5000));
        using var reader = command.ExecuteReader();
        var events = new List<MitreEventDto>();
        while (reader.Read())
        {
            events.Add(new MitreEventDto(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetString(4),
                reader.GetString(5),
                reader.GetString(6),
                reader.GetString(7),
                DateTimeOffset.Parse(reader.GetString(8)),
                DateTimeOffset.Parse(reader.GetString(9)),
                reader.GetInt32(10),
                reader.GetString(11),
                reader.GetString(12),
                reader.GetString(13),
                reader.GetString(14),
                reader.GetString(15)));
        }

        return events;
    }

    private static void UpsertFinding(
        SqliteConnection connection,
        SqliteTransaction transaction,
        DetectionFindingDto finding,
        string host)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO detection_findings (
                finding_id, rule_id, first_seen_at, last_seen_at, host,
                severity, risk_score, category, title, description, evidence,
                entity_type, entity_id, occurrence_count
            ) VALUES (
                $findingId, $ruleId, $observedAt, $observedAt, $host,
                $severity, $riskScore, $category, $title, $description,
                $evidence, $entityType, $entityId, 1
            )
            ON CONFLICT(finding_id) DO UPDATE SET
                last_seen_at = excluded.last_seen_at,
                host = excluded.host,
                severity = excluded.severity,
                risk_score = excluded.risk_score,
                category = excluded.category,
                title = excluded.title,
                description = excluded.description,
                evidence = excluded.evidence,
                occurrence_count = detection_findings.occurrence_count + 1;
            """;
        command.Parameters.AddWithValue("$findingId", finding.FindingId);
        command.Parameters.AddWithValue("$ruleId", finding.RuleId);
        command.Parameters.AddWithValue(
            "$observedAt",
            finding.ObservedAt.ToUniversalTime().ToString("O"));
        command.Parameters.AddWithValue("$host", host);
        command.Parameters.AddWithValue("$severity", finding.Severity);
        command.Parameters.AddWithValue("$riskScore", finding.RiskScore);
        command.Parameters.AddWithValue("$category", finding.Category);
        command.Parameters.AddWithValue("$title", finding.Title);
        command.Parameters.AddWithValue("$description", finding.Description);
        command.Parameters.AddWithValue("$evidence", finding.Evidence);
        command.Parameters.AddWithValue("$entityType", finding.EntityType);
        command.Parameters.AddWithValue("$entityId", finding.EntityId);
        command.ExecuteNonQuery();
    }

    private static string BuildSignature(
        IEnumerable<DetectionFindingDto> findings)
    {
        var content = string.Join(
            "\n",
            findings.Select(finding => finding.FindingId)
                .OrderBy(id => id, StringComparer.Ordinal));
        return Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(content)));
    }
}
