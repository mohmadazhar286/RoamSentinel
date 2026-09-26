using System.Text.Json;
using Microsoft.Data.Sqlite;
using RoamSentinel.Core;

namespace RoamSentinel.Database;

public sealed class AppActivityRepository(
    IDatabaseConnectionFactory connections) : IAppActivityRepository
{
    private const int UnusedAfterDays = 60;

    public AppActivityDashboardDto RecordSnapshot(
        IReadOnlyCollection<AppActivityObservationDto> observations,
        DateTimeOffset observedAt)
    {
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        foreach (var observation in observations)
        {
            var previous = ReadPrevious(connection, transaction, observation.AppId);
            var assessment = Assess(observation, observedAt, previous?.LastSeenRunningAt);
            UpsertInventory(connection, transaction, observation, assessment);
            InsertObservation(connection, transaction, observation, observedAt);
        }

        AuditSql.Insert(
            connection,
            transaction,
            "system",
            "app_activity.snapshot.recorded",
            "app_activity",
            observedAt.ToString("O"),
            true,
            JsonSerializer.Serialize(new { Apps = observations.Count }));
        transaction.Commit();
        return GetDashboard();
    }

    public AppActivityDashboardDto GetDashboard(int limit = 250)
    {
        using var connection = connections.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT app_id, name, publisher, version, install_location,
                   first_seen_at, last_seen_installed_at, last_seen_running_at,
                   last_network_activity_at, observed_run_count,
                   observed_network_count, is_currently_running,
                   current_process_count, current_network_connection_count,
                   auto_start, recommendation, risk_score, risk_reason
            FROM app_activity_inventory
            ORDER BY risk_score DESC, last_seen_installed_at DESC
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 1000));
        using var reader = command.ExecuteReader();
        var apps = new List<AppActivityDto>();
        while (reader.Read())
        {
            apps.Add(new AppActivityDto(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetString(4),
                DateTimeOffset.Parse(reader.GetString(5)),
                DateTimeOffset.Parse(reader.GetString(6)),
                reader.IsDBNull(7) ? null : DateTimeOffset.Parse(reader.GetString(7)),
                reader.IsDBNull(8) ? null : DateTimeOffset.Parse(reader.GetString(8)),
                reader.GetInt32(9),
                reader.GetInt32(10),
                reader.GetInt64(11) == 1,
                reader.GetInt32(12),
                reader.GetInt32(13),
                reader.GetInt64(14) == 1,
                DaysSince(reader.IsDBNull(7) ? null : DateTimeOffset.Parse(reader.GetString(7))),
                reader.GetString(15),
                reader.GetInt32(16),
                reader.GetString(17)));
        }

        return new AppActivityDashboardDto(
            DateTimeOffset.UtcNow,
            apps.Count,
            apps.Count(item => item.IsCurrentlyRunning),
            apps.Count(item => item.Recommendation == "review-unused"),
            apps.Count(item => item.Recommendation == "unused-but-active"),
            apps);
    }

    private static void UpsertInventory(
        SqliteConnection connection,
        SqliteTransaction transaction,
        AppActivityObservationDto observation,
        AppAssessment assessment)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO app_activity_inventory(
                app_id, name, publisher, version, install_location,
                first_seen_at, last_seen_installed_at, last_seen_running_at,
                last_network_activity_at, observed_run_count,
                observed_network_count, is_currently_running,
                current_process_count, current_network_connection_count,
                auto_start, recommendation, risk_score, risk_reason)
            VALUES(
                $id,$name,$publisher,$version,$location,$now,$now,$runningAt,
                $networkAt,$runCount,$networkCount,$running,$processCount,
                $connectionCount,$autoStart,$recommendation,$risk,$reason)
            ON CONFLICT(app_id) DO UPDATE SET
                name=excluded.name,
                publisher=excluded.publisher,
                version=excluded.version,
                install_location=excluded.install_location,
                last_seen_installed_at=excluded.last_seen_installed_at,
                last_seen_running_at=COALESCE(
                    excluded.last_seen_running_at,
                    app_activity_inventory.last_seen_running_at),
                last_network_activity_at=COALESCE(
                    excluded.last_network_activity_at,
                    app_activity_inventory.last_network_activity_at),
                observed_run_count=app_activity_inventory.observed_run_count +
                    excluded.observed_run_count,
                observed_network_count=app_activity_inventory.observed_network_count +
                    excluded.observed_network_count,
                is_currently_running=excluded.is_currently_running,
                current_process_count=excluded.current_process_count,
                current_network_connection_count=excluded.current_network_connection_count,
                auto_start=excluded.auto_start,
                recommendation=excluded.recommendation,
                risk_score=excluded.risk_score,
                risk_reason=excluded.risk_reason;
            """;
        command.Parameters.AddWithValue("$id", observation.AppId);
        command.Parameters.AddWithValue("$name", observation.Name);
        command.Parameters.AddWithValue("$publisher", observation.Publisher);
        command.Parameters.AddWithValue("$version", observation.Version);
        command.Parameters.AddWithValue("$location", observation.InstallLocation);
        command.Parameters.AddWithValue("$now", observation.ObservedAt.ToString("O"));
        command.Parameters.AddWithValue(
            "$runningAt",
            observation.IsCurrentlyRunning
                ? observation.ObservedAt.ToString("O")
                : DBNull.Value);
        command.Parameters.AddWithValue(
            "$networkAt",
            observation.CurrentNetworkConnectionCount > 0
                ? observation.ObservedAt.ToString("O")
                : DBNull.Value);
        command.Parameters.AddWithValue(
            "$runCount",
            observation.IsCurrentlyRunning ? 1 : 0);
        command.Parameters.AddWithValue(
            "$networkCount",
            observation.CurrentNetworkConnectionCount > 0 ? 1 : 0);
        command.Parameters.AddWithValue(
            "$running",
            observation.IsCurrentlyRunning ? 1 : 0);
        command.Parameters.AddWithValue(
            "$processCount",
            observation.CurrentProcessCount);
        command.Parameters.AddWithValue(
            "$connectionCount",
            observation.CurrentNetworkConnectionCount);
        command.Parameters.AddWithValue("$autoStart", observation.AutoStart ? 1 : 0);
        command.Parameters.AddWithValue("$recommendation", assessment.Recommendation);
        command.Parameters.AddWithValue("$risk", assessment.RiskScore);
        command.Parameters.AddWithValue("$reason", assessment.RiskReason);
        command.ExecuteNonQuery();
    }

    private static PreviousAppState? ReadPrevious(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string appId)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT last_seen_running_at
            FROM app_activity_inventory
            WHERE app_id=$app;
            """;
        command.Parameters.AddWithValue("$app", appId);
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        return new(reader.IsDBNull(0)
            ? null
            : DateTimeOffset.Parse(reader.GetString(0)));
    }

    private static void InsertObservation(
        SqliteConnection connection,
        SqliteTransaction transaction,
        AppActivityObservationDto observation,
        DateTimeOffset observedAt)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO app_activity_observations(
                observation_id, observed_at, app_id, is_running,
                process_count, network_connection_count, auto_start)
            VALUES($id,$observed,$app,$running,$processes,$connections,$autoStart);
            """;
        command.Parameters.AddWithValue("$id", Guid.NewGuid().ToString("N"));
        command.Parameters.AddWithValue("$observed", observedAt.ToString("O"));
        command.Parameters.AddWithValue("$app", observation.AppId);
        command.Parameters.AddWithValue("$running", observation.IsCurrentlyRunning ? 1 : 0);
        command.Parameters.AddWithValue("$processes", observation.CurrentProcessCount);
        command.Parameters.AddWithValue("$connections", observation.CurrentNetworkConnectionCount);
        command.Parameters.AddWithValue("$autoStart", observation.AutoStart ? 1 : 0);
        command.ExecuteNonQuery();
    }

    private static AppAssessment Assess(
        AppActivityObservationDto observation,
        DateTimeOffset observedAt,
        DateTimeOffset? lastSeenRunningAt)
    {
        var days = DaysSince(lastSeenRunningAt);
        if (days >= UnusedAfterDays &&
            observation.IsCurrentlyRunning &&
            observation.CurrentNetworkConnectionCount > 0)
        {
            return new(
                "unused-but-active",
                80,
                $"No observed user runtime for {days} day(s), but it is running with network activity.");
        }

        if (days >= UnusedAfterDays && observation.IsCurrentlyRunning)
        {
            return new(
                "unused-but-active",
                65,
                $"No observed user runtime for {days} day(s), but it is running now.");
        }

        if (observation.IsCurrentlyRunning && observation.CurrentNetworkConnectionCount > 0)
        {
            return new(
                "active-network",
                observation.AutoStart ? 45 : 25,
                observation.AutoStart
                    ? "Running with network activity and starts automatically."
                    : "Running with network activity.");
        }

        if (observation.IsCurrentlyRunning)
        {
            return new(
                "active",
                observation.AutoStart ? 30 : 10,
                observation.AutoStart
                    ? "Running and configured for automatic start."
                    : "Running during the latest observation.");
        }

        if (observation.AutoStart)
        {
            return new(
                "auto-start-review",
                35,
                "Not running now, but configured for startup/background execution.");
        }

        if (days >= UnusedAfterDays)
        {
            return new(
                "review-unused",
                15,
                $"No observed runtime for {days} day(s).");
        }

        return new("normal", 0, "No background activity concern.");
    }

    private static int? DaysSince(DateTimeOffset? timestamp) =>
        timestamp is null
            ? null
            : Math.Max(0, (int)(DateTimeOffset.UtcNow - timestamp.Value).TotalDays);

    private sealed record AppAssessment(
        string Recommendation,
        int RiskScore,
        string RiskReason);

    private sealed record PreviousAppState(DateTimeOffset? LastSeenRunningAt);
}
