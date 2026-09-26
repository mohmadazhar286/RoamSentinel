using System.Text.Json;
using Microsoft.Data.Sqlite;
using RoamSentinel.Core;

namespace RoamSentinel.Database;

public sealed class DeviceIntegrityFindingRepository(
    IDatabaseConnectionFactory connections) : IDeviceIntegrityFindingRepository
{
    private static readonly HashSet<string> AllowedStatuses = new(
        ["open", "expected", "suppressed", "resolved"],
        StringComparer.OrdinalIgnoreCase);

    public IReadOnlyList<DeviceIntegrityFindingDto> RecordFromChanges(
        IReadOnlyCollection<DeviceIntegrityChangeEvent> changes)
    {
        if (changes.Count == 0)
        {
            return [];
        }

        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        var recorded = new List<DeviceIntegrityFindingDto>();
        foreach (var change in changes)
        {
            var finding = CreateFinding(change);
            if (Insert(connection, transaction, finding, change.EventId))
            {
                recorded.Add(finding);
            }
        }

        AuditSql.Insert(
            connection,
            transaction,
            "system",
            "device_integrity.findings.projected",
            "device_integrity",
            "*",
            true,
            JsonSerializer.Serialize(new
            {
                Changes = changes.Count,
                Findings = recorded.Count
            }));
        transaction.Commit();
        return recorded;
    }

    public IReadOnlyList<DeviceIntegrityFindingDto> GetRecent(int limit)
    {
        using var connection = connections.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT finding_id, observed_at, severity, risk_score, entity_type,
                   entity_key, change_type, title, explanation, status,
                   resolution_note, resolved_at, resolved_by
            FROM device_integrity_findings
            ORDER BY observed_at DESC
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 1000));
        using var reader = command.ExecuteReader();
        var result = new List<DeviceIntegrityFindingDto>();
        while (reader.Read())
        {
            result.Add(Read(reader));
        }

        return result;
    }

    public DeviceIntegrityFindingDto? SetStatus(
        string findingId,
        string status,
        string note,
        string actor)
    {
        actor = string.IsNullOrWhiteSpace(actor) ? "local-user" : actor;
        note ??= "";
        var normalizedStatus = status ?? "";
        if (string.IsNullOrWhiteSpace(findingId) ||
            !AllowedStatuses.Contains(normalizedStatus))
        {
            throw new ArgumentException("Invalid Device Integrity finding status.");
        }
        normalizedStatus = normalizedStatus.ToLowerInvariant();

        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE device_integrity_findings
            SET status=$status,
                resolution_note=$note,
                resolved_at=$resolvedAt,
                resolved_by=$actor
            WHERE finding_id=$findingId;
            """;
        command.Parameters.AddWithValue("$status", normalizedStatus);
        command.Parameters.AddWithValue("$note", note);
        command.Parameters.AddWithValue(
            "$resolvedAt",
            normalizedStatus.Equals("open", StringComparison.OrdinalIgnoreCase)
                ? DBNull.Value
                : DateTimeOffset.UtcNow.ToString("O"));
        command.Parameters.AddWithValue("$actor", actor);
        command.Parameters.AddWithValue("$findingId", findingId);
        if (command.ExecuteNonQuery() == 0)
        {
            transaction.Rollback();
            return null;
        }

        AuditSql.Insert(
            connection,
            transaction,
            actor,
            "device_integrity.finding_status_changed",
            "device_integrity_finding",
            findingId,
            true,
            JsonSerializer.Serialize(new { Status = status, Note = note }));
        transaction.Commit();
        return GetRecent(1000).FirstOrDefault(item => item.FindingId == findingId);
    }

    private static DeviceIntegrityFindingDto CreateFinding(
        DeviceIntegrityChangeEvent change)
    {
        var (severity, risk, title) = Classify(change);
        return new(
            $"dif-{change.EventId}",
            change.ObservedAt,
            severity,
            risk,
            change.EntityType,
            change.EntityKey,
            change.ChangeType,
            title,
            BuildExplanation(change, severity),
            "open",
            "",
            null,
            "");
    }

    private static (string Severity, int Risk, string Title) Classify(
        DeviceIntegrityChangeEvent change)
    {
        if (change.EntityType == "firewall-profile")
        {
            return ("High", 75, "Firewall profile changed");
        }

        if (change.EntityType == "service" &&
            change.ChangeType is "added" or "changed")
        {
            return ("High", 70, "Windows service integrity changed");
        }

        if (change.EntityType == "scheduled-task" &&
            change.ChangeType is "added" or "changed")
        {
            return ("Medium", 55, "Scheduled task integrity changed");
        }

        if (change.EntityType == "registry-persistence")
        {
            return ("High", 72, "Registry persistence changed");
        }

        if (change.EntityType == "network-listener" &&
            change.ChangeType == "added")
        {
            return ("Medium", 50, "Network listener added");
        }

        if (change.EntityType == "powershell")
        {
            return ("Medium", 45, "PowerShell posture changed");
        }

        if (change.EntityType == "driver")
        {
            return ("Medium", 60, "Driver inventory changed");
        }

        return ("Low", 25, "Device integrity baseline changed");
    }

    private static string BuildExplanation(
        DeviceIntegrityChangeEvent change,
        string severity) =>
        $"{severity} Device Integrity finding: {change.EntityType} " +
        $"'{change.EntityKey}' was {change.ChangeType}. Review whether this " +
        "change is expected before taking response action.";

    private static bool Insert(
        SqliteConnection connection,
        SqliteTransaction transaction,
        DeviceIntegrityFindingDto item,
        string sourceEventId)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT OR IGNORE INTO device_integrity_findings(
                finding_id, source_event_id, observed_at, severity, risk_score,
                entity_type, entity_key, change_type, title, explanation)
            VALUES(
                $id, $eventId, $observedAt, $severity, $riskScore,
                $entityType, $entityKey, $changeType, $title, $explanation);
            """;
        command.Parameters.AddWithValue("$id", item.FindingId);
        command.Parameters.AddWithValue("$eventId", sourceEventId);
        command.Parameters.AddWithValue("$observedAt", item.ObservedAt.ToString("O"));
        command.Parameters.AddWithValue("$severity", item.Severity);
        command.Parameters.AddWithValue("$riskScore", item.RiskScore);
        command.Parameters.AddWithValue("$entityType", item.EntityType);
        command.Parameters.AddWithValue("$entityKey", item.EntityKey);
        command.Parameters.AddWithValue("$changeType", item.ChangeType);
        command.Parameters.AddWithValue("$title", item.Title);
        command.Parameters.AddWithValue("$explanation", item.Explanation);
        return command.ExecuteNonQuery() > 0;
    }

    private static DeviceIntegrityFindingDto Read(SqliteDataReader reader) =>
        new(
            reader.GetString(0),
            DateTimeOffset.Parse(reader.GetString(1)),
            reader.GetString(2),
            reader.GetInt32(3),
            reader.GetString(4),
            reader.GetString(5),
            reader.GetString(6),
            reader.GetString(7),
            reader.GetString(8),
            reader.GetString(9),
            reader.GetString(10),
            reader.IsDBNull(11) ? null : DateTimeOffset.Parse(reader.GetString(11)),
            reader.GetString(12));
}
