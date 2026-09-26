using System.Text.Json;
using RoamSentinel.Core;

namespace RoamSentinel.Database;

public sealed class ProtectionSchedulerRepository(
    IDatabaseConnectionFactory connections) : IProtectionSchedulerRepository
{
    public void EnsureTasks(IReadOnlyCollection<SchedulerTaskStatusDto> tasks)
    {
        var now = DateTimeOffset.UtcNow;
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        foreach (var task in tasks)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO protection_scheduler_tasks (
                    task_key, display_name, enabled, interval_seconds,
                    next_run_at, updated_at
                ) VALUES (
                    $taskKey, $displayName, $enabled, $intervalSeconds,
                    $nextRunAt, $updatedAt
                )
                ON CONFLICT(task_key) DO UPDATE SET
                    display_name = excluded.display_name,
                    enabled = excluded.enabled,
                    interval_seconds = excluded.interval_seconds,
                    next_run_at = COALESCE(
                        protection_scheduler_tasks.next_run_at,
                        excluded.next_run_at),
                    updated_at = excluded.updated_at;
                """;
            command.Parameters.AddWithValue("$taskKey", task.TaskKey);
            command.Parameters.AddWithValue("$displayName", task.DisplayName);
            command.Parameters.AddWithValue("$enabled", task.Enabled ? 1 : 0);
            command.Parameters.AddWithValue(
                "$intervalSeconds",
                task.IntervalSeconds);
            command.Parameters.AddWithValue(
                "$nextRunAt",
                ToSql(task.NextRunAt ?? now));
            command.Parameters.AddWithValue("$updatedAt", ToSql(now));
            command.ExecuteNonQuery();
        }

        transaction.Commit();
    }

    public void MarkStarted(string taskKey, DateTimeOffset startedAt)
    {
        using var connection = connections.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE protection_scheduler_tasks
            SET last_started_at = $startedAt,
                last_status = 'running',
                updated_at = $startedAt
            WHERE task_key = $taskKey;
            """;
        command.Parameters.AddWithValue("$taskKey", taskKey);
        command.Parameters.AddWithValue("$startedAt", ToSql(startedAt));
        command.ExecuteNonQuery();
    }

    public void MarkCompleted(
        string taskKey,
        DateTimeOffset completedAt,
        bool success,
        string status,
        string message,
        DateTimeOffset nextRunAt)
    {
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE protection_scheduler_tasks
            SET last_completed_at = $completedAt,
                next_run_at = $nextRunAt,
                last_success = $success,
                last_status = $status,
                last_message = $message,
                success_count = success_count + $successIncrement,
                failure_count = failure_count + $failureIncrement,
                updated_at = $completedAt
            WHERE task_key = $taskKey;
            """;
        command.Parameters.AddWithValue("$taskKey", taskKey);
        command.Parameters.AddWithValue("$completedAt", ToSql(completedAt));
        command.Parameters.AddWithValue("$nextRunAt", ToSql(nextRunAt));
        command.Parameters.AddWithValue("$success", success ? 1 : 0);
        command.Parameters.AddWithValue("$status", status);
        command.Parameters.AddWithValue("$message", Truncate(message, 600));
        command.Parameters.AddWithValue("$successIncrement", success ? 1 : 0);
        command.Parameters.AddWithValue("$failureIncrement", success ? 0 : 1);
        command.ExecuteNonQuery();
        AuditSql.Insert(
            connection,
            transaction,
            "scheduler",
            success ? "scheduler.task.completed" : "scheduler.task.failed",
            "protection_scheduler_task",
            taskKey,
            success,
            JsonSerializer.Serialize(new
            {
                Status = status,
                Message = Truncate(message, 600),
                NextRunAt = nextRunAt
            }));
        transaction.Commit();
    }

    public SchedulerDashboardDto GetDashboard(bool enabled)
    {
        using var connection = connections.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT task_key, display_name, enabled, interval_seconds,
                   last_started_at, last_completed_at, next_run_at,
                   last_success, last_status, last_message,
                   success_count, failure_count
            FROM protection_scheduler_tasks
            ORDER BY task_key;
            """;
        using var reader = command.ExecuteReader();
        var tasks = new List<SchedulerTaskStatusDto>();
        while (reader.Read())
        {
            tasks.Add(new SchedulerTaskStatusDto(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetInt32(2) == 1,
                reader.GetInt32(3),
                ReadDate(reader, 4),
                ReadDate(reader, 5),
                ReadDate(reader, 6),
                reader.GetInt32(7) == 1,
                reader.GetString(8),
                reader.GetString(9),
                reader.GetInt32(10),
                reader.GetInt32(11)));
        }

        return new SchedulerDashboardDto(
            enabled,
            DateTimeOffset.UtcNow,
            tasks);
    }

    private static DateTimeOffset? ReadDate(
        Microsoft.Data.Sqlite.SqliteDataReader reader,
        int ordinal) =>
        reader.IsDBNull(ordinal)
            ? null
            : DateTimeOffset.Parse(reader.GetString(ordinal));

    private static string ToSql(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("O");

    private static string Truncate(string value, int maxLength) =>
        string.IsNullOrEmpty(value) || value.Length <= maxLength
            ? value
            : value[..maxLength];
}
