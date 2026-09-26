using System.Text.Json;
using RoamSentinel.Core;

namespace RoamSentinel.Database;

public sealed class DisabledStartupRepository(
    IDatabaseConnectionFactory connections) : IDisabledStartupRepository
{
    public void Record(DisabledStartupItemRecord item)
    {
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO disabled_startup_items (
                disable_id, source_type, source, item_name, original_value,
                backup_path, disabled_at, disabled_by
            ) VALUES (
                $disableId, $sourceType, $source, $itemName, $originalValue,
                $backupPath, $disabledAt, $disabledBy
            );
            """;
        command.Parameters.AddWithValue("$disableId", item.DisableId);
        command.Parameters.AddWithValue("$sourceType", item.SourceType);
        command.Parameters.AddWithValue("$source", item.Source);
        command.Parameters.AddWithValue("$itemName", item.ItemName);
        command.Parameters.AddWithValue("$originalValue", item.OriginalValue);
        command.Parameters.AddWithValue("$backupPath", item.BackupPath);
        command.Parameters.AddWithValue(
            "$disabledAt",
            item.DisabledAt.ToUniversalTime().ToString("O"));
        command.Parameters.AddWithValue("$disabledBy", item.DisabledBy);
        command.ExecuteNonQuery();
        AuditSql.Insert(
            connection,
            transaction,
            item.DisabledBy,
            "startup_item.disabled",
            "startup_item",
            item.DisableId,
            true,
            JsonSerializer.Serialize(new
            {
                item.SourceType,
                item.Source,
                item.ItemName,
                item.BackupPath
            }));
        transaction.Commit();
    }
}
