using System.Text.Json;
using RoamSentinel.Core;

namespace RoamSentinel.Database;

public sealed class EventRepository(
    IDatabaseConnectionFactory connections) : IEventRepository
{
    public bool TryAdd(AlertDto alert)
    {
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
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
        AddEventParameters(command, alert);
        var inserted = command.ExecuteNonQuery() > 0;
        if (inserted)
        {
            AuditSql.Insert(
                connection,
                transaction,
                "system",
                "security_event.created",
                "security_event",
                alert.Id,
                true,
                JsonSerializer.Serialize(new
                {
                    alert.Category,
                    alert.Severity,
                    alert.Title
                }));
        }

        transaction.Commit();
        return inserted;
    }

    public void AddOrUpdate(AlertDto alert)
    {
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO security_events (
                event_id, occurred_at, last_seen_at, category, severity,
                title, detail, occurrence_count
            ) VALUES (
                $id, $occurredAt, $lastSeenAt, $category, $severity,
                $title, $detail, 1
            )
            ON CONFLICT(event_id) DO UPDATE SET
                last_seen_at = excluded.last_seen_at,
                category = excluded.category,
                severity = excluded.severity,
                title = excluded.title,
                detail = excluded.detail,
                occurrence_count = security_events.occurrence_count + 1;
            """;
        AddEventParameters(command, alert);
        command.ExecuteNonQuery();
        AuditSql.Insert(
            connection,
            transaction,
            "system",
            "security_event.upserted",
            "security_event",
            alert.Id,
            true,
            JsonSerializer.Serialize(new
            {
                alert.Category,
                alert.Severity,
                alert.Title
            }));
        transaction.Commit();
    }

    public IReadOnlyList<AlertDto> GetRecent(int limit)
    {
        using var connection = connections.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT event_id, occurred_at, category, severity, title, detail
            FROM security_events
            ORDER BY occurred_at DESC
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$limit", limit);

        using var reader = command.ExecuteReader();
        var events = new List<AlertDto>();
        while (reader.Read())
        {
            events.Add(new AlertDto(
                reader.GetString(0),
                DateTimeOffset.Parse(reader.GetString(1)),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetString(4),
                reader.GetString(5)));
        }

        return events;
    }

    public AlertStateDto? GetState(string alertId)
    {
        using var connection = connections.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT event_id, status, resolution_note, resolved_at, resolved_by
            FROM security_events
            WHERE event_id = $alertId;
            """;
        command.Parameters.AddWithValue("$alertId", alertId);
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadState(reader) : null;
    }

    public AlertStateDto? SetDisposition(
        string alertId,
        string status,
        string note,
        string actor)
    {
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE security_events
            SET status = $status,
                resolution_note = $note,
                resolved_at = $resolvedAt,
                resolved_by = $actor
            WHERE event_id = $alertId;
            """;
        command.Parameters.AddWithValue("$status", status);
        command.Parameters.AddWithValue("$note", note);
        command.Parameters.AddWithValue(
            "$resolvedAt",
            DateTimeOffset.UtcNow.ToString("O"));
        command.Parameters.AddWithValue("$actor", actor);
        command.Parameters.AddWithValue("$alertId", alertId);
        if (command.ExecuteNonQuery() == 0)
        {
            transaction.Rollback();
            return null;
        }

        AuditSql.Insert(
            connection,
            transaction,
            actor,
            "security_event.disposition_changed",
            "security_event",
            alertId,
            true,
            JsonSerializer.Serialize(new { Status = status, Note = note }));
        transaction.Commit();
        return GetState(alertId);
    }

    public int Purge()
    {
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "DELETE FROM security_events;";
        var eventCount = command.ExecuteNonQuery();
        using var findings = connection.CreateCommand();
        findings.Transaction = transaction;
        findings.CommandText = "DELETE FROM detection_findings;";
        var findingCount = findings.ExecuteNonQuery();
        var count = eventCount + findingCount;
        AuditSql.Insert(
            connection,
            transaction,
            "local-user",
            "security_events.purged",
            "security_event",
            "*",
            true,
            JsonSerializer.Serialize(new
            {
                SecurityEvents = eventCount,
                DetectionFindings = findingCount,
                DeletedCount = count
            }));
        transaction.Commit();
        return count;
    }

    private static void AddEventParameters(
        Microsoft.Data.Sqlite.SqliteCommand command,
        AlertDto alert)
    {
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
    }

    private static AlertStateDto ReadState(
        Microsoft.Data.Sqlite.SqliteDataReader reader) =>
        new(
            reader.GetString(0),
            reader.GetString(1),
            reader.GetString(2),
            reader.IsDBNull(3)
                ? null
                : DateTimeOffset.Parse(reader.GetString(3)),
            reader.GetString(4));
}
