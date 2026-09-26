using Microsoft.Data.Sqlite;

namespace RoamSentinel.Database;

internal static class AuditSql
{
    public static void Insert(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string actor,
        string action,
        string entityType,
        string entityId,
        bool success,
        string detailJson)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO audit_log (
                audit_id, occurred_at, actor, action, entity_type,
                entity_id, success, detail_json
            ) VALUES (
                $auditId, $occurredAt, $actor, $action, $entityType,
                $entityId, $success, $detailJson
            );
            """;
        command.Parameters.AddWithValue("$auditId", Guid.NewGuid().ToString("N"));
        command.Parameters.AddWithValue(
            "$occurredAt",
            DateTimeOffset.UtcNow.ToString("O"));
        command.Parameters.AddWithValue("$actor", actor);
        command.Parameters.AddWithValue("$action", action);
        command.Parameters.AddWithValue("$entityType", entityType);
        command.Parameters.AddWithValue("$entityId", entityId);
        command.Parameters.AddWithValue("$success", success ? 1 : 0);
        command.Parameters.AddWithValue("$detailJson", detailJson);
        command.ExecuteNonQuery();
    }
}
