using Microsoft.Data.Sqlite;
using RoamSentinel.Core;

namespace RoamSentinel.Database;

public sealed class AuditRepository(
    IDatabaseConnectionFactory connections) : IAuditRepository
{
    public void Write(
        string actor,
        string action,
        string entityType,
        string entityId,
        bool success,
        string detailJson)
    {
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        AuditSql.Insert(
            connection,
            transaction,
            actor,
            action,
            entityType,
            entityId,
            success,
            detailJson);
        transaction.Commit();
    }

    public IReadOnlyList<AuditLogEntryDto> GetRecent(int limit)
    {
        using var connection = connections.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT audit_id, occurred_at, actor, action, entity_type,
                   entity_id, success, detail_json
            FROM audit_log
            ORDER BY occurred_at DESC
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$limit", limit);

        using var reader = command.ExecuteReader();
        var entries = new List<AuditLogEntryDto>();
        while (reader.Read())
        {
            entries.Add(new AuditLogEntryDto(
                reader.GetString(0),
                DateTimeOffset.Parse(reader.GetString(1)),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetString(4),
                reader.GetString(5),
                reader.GetInt64(6) == 1,
                reader.GetString(7)));
        }

        return entries;
    }
}
