using System.Text.Json;
using RoamSentinel.Core;

namespace RoamSentinel.Database;

public sealed class ResponseActionRepository(
    IDatabaseConnectionFactory connections,
    IStructuredLogService logs) : IResponseActionRepository
{
    public void Record(ResponseActionRecord action)
    {
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO response_actions (
                action_id, requested_at, completed_at, action_type, target,
                status, success, output, error, requested_by,
                before_json, after_json
            ) VALUES (
                $actionId, $requestedAt, $completedAt, $actionType, $target,
                $status, $success, $output, $error, $requestedBy,
                $beforeJson, $afterJson
            );
            """;
        command.Parameters.AddWithValue("$actionId", action.ActionId);
        command.Parameters.AddWithValue(
            "$requestedAt",
            action.RequestedAt.ToUniversalTime().ToString("O"));
        command.Parameters.AddWithValue(
            "$completedAt",
            action.CompletedAt.ToUniversalTime().ToString("O"));
        command.Parameters.AddWithValue("$actionType", action.ActionType);
        command.Parameters.AddWithValue("$target", action.Target);
        command.Parameters.AddWithValue("$status", action.Status);
        command.Parameters.AddWithValue("$success", action.Success ? 1 : 0);
        command.Parameters.AddWithValue("$output", action.Output);
        command.Parameters.AddWithValue("$error", action.Error);
        command.Parameters.AddWithValue("$requestedBy", action.RequestedBy);
        command.Parameters.AddWithValue("$beforeJson", action.BeforeJson);
        command.Parameters.AddWithValue("$afterJson", action.AfterJson);
        command.ExecuteNonQuery();
        AuditSql.Insert(
            connection,
            transaction,
            action.RequestedBy,
            $"response.{action.ActionType}",
            "response_action",
            action.ActionId,
            action.Success,
            JsonSerializer.Serialize(new
            {
                action.ActionType,
                action.Target,
                action.Status,
                Before = JsonSerializer.Deserialize<JsonElement>(
                    action.BeforeJson),
                After = JsonSerializer.Deserialize<JsonElement>(
                    action.AfterJson)
            }));
        transaction.Commit();
        logs.Response(
            action.ActionType,
            action.Success
                ? "Response action completed."
                : "Response action failed or was denied.",
            new
            {
                action.ActionId,
                action.Target,
                action.Status,
                action.Success,
                action.RequestedBy,
                action.Error
            });
    }

    public IReadOnlyList<ResponseActionRecord> GetRecent(int limit)
    {
        using var connection = connections.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT action_id, requested_at, completed_at, action_type, target,
                   status, success, output, error, requested_by,
                   before_json, after_json
            FROM response_actions
            ORDER BY requested_at DESC
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 1000));
        using var reader = command.ExecuteReader();
        var actions = new List<ResponseActionRecord>();
        while (reader.Read())
        {
            actions.Add(new ResponseActionRecord(
                reader.GetString(0),
                DateTimeOffset.Parse(reader.GetString(1)),
                DateTimeOffset.Parse(reader.GetString(2)),
                reader.GetString(3),
                reader.GetString(4),
                reader.GetString(5),
                reader.GetInt32(6) == 1,
                reader.GetString(7),
                reader.GetString(8),
                reader.GetString(9),
                reader.GetString(10),
                reader.GetString(11)));
        }

        return actions;
    }
}
