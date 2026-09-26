using System.Text.Json;
using Microsoft.Data.Sqlite;
using RoamSentinel.Config;
using RoamSentinel.Core;

namespace RoamSentinel.Database;

public sealed class TelemetryRepository(
    IDatabaseConnectionFactory connections,
    DatabaseOptions options) : ITelemetryRepository
{
    private readonly Lock _gate = new();
    private DateTimeOffset _lastPersisted = DateTimeOffset.MinValue;

    public bool PersistSnapshot(TelemetrySnapshot snapshot)
    {
        if (!options.PersistTelemetrySnapshots)
        {
            return false;
        }

        lock (_gate)
        {
            if (snapshot.ObservedAt - _lastPersisted <
                TimeSpan.FromSeconds(
                    options.TelemetryPersistenceIntervalSeconds))
            {
                return false;
            }

            using var connection = connections.OpenConnection();
            using var transaction = connection.BeginTransaction();
            InsertProcesses(
                connection,
                transaction,
                snapshot.Processes,
                snapshot.ObservedAt);
            InsertNetwork(
                connection,
                transaction,
                snapshot.Connections,
                snapshot.ObservedAt);
            InsertStartup(
                connection,
                transaction,
                snapshot.StartupEntries,
                snapshot.ObservedAt);
            InsertScheduledTasks(connection, transaction, snapshot);
            InsertServices(connection, transaction, snapshot);
            InsertDefender(connection, transaction, snapshot);
            InsertFirewall(connection, transaction, snapshot);
            InsertAgents(connection, transaction, snapshot);
            InsertSuspiciousPaths(connection, transaction, snapshot);
            DeleteExpired(connection, transaction, snapshot.ObservedAt);
            AuditSql.Insert(
                connection,
                transaction,
                "system",
                "telemetry.snapshot.persisted",
                "telemetry_snapshot",
                snapshot.ObservedAt.ToUniversalTime().ToString("O"),
                true,
                JsonSerializer.Serialize(new
                {
                    Processes = snapshot.Processes.Count,
                    Network = snapshot.Connections.Count,
                    Startup = snapshot.StartupEntries.Count,
                    ScheduledTasks = snapshot.ScheduledTasks.Count,
                    Services = snapshot.Services.Count,
                    FirewallProfiles = snapshot.Firewall.Profiles.Count,
                    InstalledAgents = snapshot.InstalledAgents.Count,
                    SuspiciousPaths = snapshot.SuspiciousPaths.Count,
                    RetentionDays = options.TelemetryRetentionDays
                }));
            transaction.Commit();
            _lastPersisted = snapshot.ObservedAt;
            return true;
        }
    }

    private static void InsertProcesses(
        SqliteConnection connection,
        SqliteTransaction transaction,
        IEnumerable<ProcessTelemetry> processes,
        DateTimeOffset observedAt)
    {
        foreach (var process in processes)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO telemetry_processes (
                    observed_at, process_id, name, executable_path, memory_mb,
                    private_memory_mb, cpu_percent, handle_count, thread_count,
                    connection_count, started_at, parent_process_id,
                    parent_process_name, command_line
                ) VALUES (
                    $observedAt, $processId, $name, $path, $memoryMb,
                    $privateMemoryMb, $cpuPercent, $handleCount, $threadCount,
                    $connectionCount, $startedAt, $parentProcessId,
                    $parentProcessName, $commandLine
                );
                """;
            command.Parameters.AddWithValue("$observedAt", ToSql(observedAt));
            command.Parameters.AddWithValue("$processId", process.ProcessId);
            command.Parameters.AddWithValue("$name", process.Name);
            command.Parameters.AddWithValue("$path", process.Path);
            command.Parameters.AddWithValue("$memoryMb", process.MemoryMb);
            command.Parameters.AddWithValue(
                "$privateMemoryMb",
                process.PrivateMemoryMb);
            command.Parameters.AddWithValue("$cpuPercent", process.CpuPercent);
            command.Parameters.AddWithValue("$handleCount", process.HandleCount);
            command.Parameters.AddWithValue("$threadCount", process.ThreadCount);
            command.Parameters.AddWithValue(
                "$connectionCount",
                process.ConnectionCount);
            command.Parameters.AddWithValue(
                "$startedAt",
                process.StartedAt is null
                    ? DBNull.Value
                    : ToSql(process.StartedAt.Value));
            command.Parameters.AddWithValue(
                "$parentProcessId",
                process.ParentProcessId);
            command.Parameters.AddWithValue(
                "$parentProcessName",
                process.ParentProcessName);
            command.Parameters.AddWithValue(
                "$commandLine",
                process.CommandLine);
            command.ExecuteNonQuery();
        }
    }

    private static void InsertNetwork(
        SqliteConnection connection,
        SqliteTransaction transaction,
        IEnumerable<ConnectionTelemetry> network,
        DateTimeOffset observedAt)
    {
        foreach (var item in network)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO telemetry_network (
                    observed_at, protocol, local_address, local_port,
                    remote_address, remote_port, state, process_id,
                    process_name, process_path
                ) VALUES (
                    $observedAt, $protocol, $localAddress, $localPort,
                    $remoteAddress, $remotePort, $state, $processId,
                    $processName, $processPath
                );
                """;
            command.Parameters.AddWithValue("$observedAt", ToSql(observedAt));
            command.Parameters.AddWithValue("$protocol", item.Protocol);
            command.Parameters.AddWithValue("$localAddress", item.LocalAddress);
            command.Parameters.AddWithValue("$localPort", item.LocalPort);
            command.Parameters.AddWithValue("$remoteAddress", item.RemoteAddress);
            command.Parameters.AddWithValue("$remotePort", item.RemotePort);
            command.Parameters.AddWithValue("$state", item.State);
            command.Parameters.AddWithValue("$processId", item.ProcessId);
            command.Parameters.AddWithValue("$processName", item.ProcessName);
            command.Parameters.AddWithValue("$processPath", item.ProcessPath);
            command.ExecuteNonQuery();
        }
    }

    private static void InsertStartup(
        SqliteConnection connection,
        SqliteTransaction transaction,
        IEnumerable<StartupTelemetry> startupEntries,
        DateTimeOffset observedAt)
    {
        foreach (var item in startupEntries)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO telemetry_startup (
                    observed_at, name, command, source
                ) VALUES (
                    $observedAt, $name, $command, $source
                );
                """;
            command.Parameters.AddWithValue("$observedAt", ToSql(observedAt));
            command.Parameters.AddWithValue("$name", item.Name);
            command.Parameters.AddWithValue("$command", item.Command);
            command.Parameters.AddWithValue("$source", item.Source);
            command.ExecuteNonQuery();
        }
    }

    private void DeleteExpired(
        SqliteConnection connection,
        SqliteTransaction transaction,
        DateTimeOffset observedAt)
    {
        var cutoff = ToSql(
            observedAt.AddDays(-options.TelemetryRetentionDays));
        foreach (var table in new[]
        {
            "telemetry_processes",
            "telemetry_network",
            "telemetry_startup",
            "telemetry_scheduled_tasks",
            "telemetry_services",
            "telemetry_defender",
            "telemetry_firewall",
            "telemetry_ai_agents",
            "telemetry_suspicious_paths"
        })
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText =
                $"DELETE FROM {table} WHERE observed_at < $cutoff;";
            command.Parameters.AddWithValue("$cutoff", cutoff);
            command.ExecuteNonQuery();
        }
    }

    private static string ToSql(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("O");

    private static void InsertScheduledTasks(
        SqliteConnection connection,
        SqliteTransaction transaction,
        TelemetrySnapshot snapshot)
    {
        foreach (var item in snapshot.ScheduledTasks)
        {
            using var command = CreateCommand(
                connection,
                transaction,
                """
                INSERT INTO telemetry_scheduled_tasks (
                    observed_at, name, task_path, state, enabled, author,
                    command, arguments, trigger_summary
                ) VALUES (
                    $observedAt, $name, $path, $state, $enabled, $author,
                    $command, $arguments, $trigger
                );
                """,
                snapshot.ObservedAt);
            command.Parameters.AddWithValue("$name", item.Name);
            command.Parameters.AddWithValue("$path", item.Path);
            command.Parameters.AddWithValue("$state", item.State);
            command.Parameters.AddWithValue("$enabled", item.Enabled ? 1 : 0);
            command.Parameters.AddWithValue("$author", item.Author);
            command.Parameters.AddWithValue("$command", item.Command);
            command.Parameters.AddWithValue("$arguments", item.Arguments);
            command.Parameters.AddWithValue("$trigger", item.Trigger);
            command.ExecuteNonQuery();
        }
    }

    private static void InsertServices(
        SqliteConnection connection,
        SqliteTransaction transaction,
        TelemetrySnapshot snapshot)
    {
        foreach (var item in snapshot.Services)
        {
            using var command = CreateCommand(
                connection,
                transaction,
                """
                INSERT INTO telemetry_services (
                    observed_at, name, display_name, state, start_mode,
                    executable_path, process_id, account
                ) VALUES (
                    $observedAt, $name, $displayName, $state, $startMode,
                    $path, $processId, $account
                );
                """,
                snapshot.ObservedAt);
            command.Parameters.AddWithValue("$name", item.Name);
            command.Parameters.AddWithValue("$displayName", item.DisplayName);
            command.Parameters.AddWithValue("$state", item.State);
            command.Parameters.AddWithValue("$startMode", item.StartMode);
            command.Parameters.AddWithValue("$path", item.Path);
            command.Parameters.AddWithValue("$processId", item.ProcessId);
            command.Parameters.AddWithValue("$account", item.Account);
            command.ExecuteNonQuery();
        }
    }

    private static void InsertDefender(
        SqliteConnection connection,
        SqliteTransaction transaction,
        TelemetrySnapshot snapshot)
    {
        var item = snapshot.Defender;
        using var command = CreateCommand(
            connection,
            transaction,
            """
            INSERT INTO telemetry_defender (
                observed_at, service_enabled, antivirus_enabled,
                realtime_enabled, network_inspection_enabled, quick_scan_age,
                full_scan_age, signature_updated_at, signature_version, message
            ) VALUES (
                $observedAt, $service, $antivirus, $realtime, $network,
                $quickAge, $fullAge, $signatureAt, $signatureVersion, $message
            );
            """,
            snapshot.ObservedAt);
        command.Parameters.AddWithValue("$service", item.ServiceEnabled ? 1 : 0);
        command.Parameters.AddWithValue("$antivirus", item.AntivirusEnabled ? 1 : 0);
        command.Parameters.AddWithValue("$realtime", item.RealTimeProtectionEnabled ? 1 : 0);
        command.Parameters.AddWithValue("$network", item.NetworkInspectionEnabled ? 1 : 0);
        command.Parameters.AddWithValue("$quickAge", (object?)item.QuickScanAge ?? DBNull.Value);
        command.Parameters.AddWithValue("$fullAge", (object?)item.FullScanAge ?? DBNull.Value);
        command.Parameters.AddWithValue(
            "$signatureAt",
            item.SignatureLastUpdated is null
                ? DBNull.Value
                : ToSql(item.SignatureLastUpdated.Value));
        command.Parameters.AddWithValue("$signatureVersion", item.SignatureVersion);
        command.Parameters.AddWithValue("$message", item.Message);
        command.ExecuteNonQuery();
    }

    private static void InsertFirewall(
        SqliteConnection connection,
        SqliteTransaction transaction,
        TelemetrySnapshot snapshot)
    {
        var profiles = snapshot.Firewall.Profiles.Count == 0
            ? [new FirewallProfileTelemetry("", false, "", "", false)]
            : snapshot.Firewall.Profiles;
        foreach (var item in profiles)
        {
            using var command = CreateCommand(
                connection,
                transaction,
                """
                INSERT INTO telemetry_firewall (
                    observed_at, profile_name, enabled, default_inbound_action,
                    default_outbound_action, notifications_disabled, available,
                    message
                ) VALUES (
                    $observedAt, $name, $enabled, $inbound, $outbound,
                    $notificationsDisabled, $available, $message
                );
                """,
                snapshot.ObservedAt);
            command.Parameters.AddWithValue("$name", item.Name);
            command.Parameters.AddWithValue("$enabled", item.Enabled ? 1 : 0);
            command.Parameters.AddWithValue("$inbound", item.DefaultInboundAction);
            command.Parameters.AddWithValue("$outbound", item.DefaultOutboundAction);
            command.Parameters.AddWithValue(
                "$notificationsDisabled",
                item.NotificationsDisabled ? 1 : 0);
            command.Parameters.AddWithValue(
                "$available",
                snapshot.Firewall.Available ? 1 : 0);
            command.Parameters.AddWithValue("$message", snapshot.Firewall.Message);
            command.ExecuteNonQuery();
        }
    }

    private static void InsertAgents(
        SqliteConnection connection,
        SqliteTransaction transaction,
        TelemetrySnapshot snapshot)
    {
        foreach (var item in snapshot.InstalledAgents)
        {
            using var command = CreateCommand(
                connection,
                transaction,
                """
                INSERT INTO telemetry_ai_agents (
                    observed_at, name, executable_path, version, publisher,
                    source, is_running, process_id
                ) VALUES (
                    $observedAt, $name, $path, $version, $publisher,
                    $source, $isRunning, $processId
                );
                """,
                snapshot.ObservedAt);
            command.Parameters.AddWithValue("$name", item.Name);
            command.Parameters.AddWithValue("$path", item.Path);
            command.Parameters.AddWithValue("$version", item.Version);
            command.Parameters.AddWithValue("$publisher", item.Publisher);
            command.Parameters.AddWithValue("$source", item.Source);
            command.Parameters.AddWithValue("$isRunning", item.IsRunning ? 1 : 0);
            command.Parameters.AddWithValue(
                "$processId",
                item.ProcessId is null ? DBNull.Value : item.ProcessId.Value);
            command.ExecuteNonQuery();
        }
    }

    private static void InsertSuspiciousPaths(
        SqliteConnection connection,
        SqliteTransaction transaction,
        TelemetrySnapshot snapshot)
    {
        foreach (var item in snapshot.SuspiciousPaths)
        {
            using var command = CreateCommand(
                connection,
                transaction,
                """
                INSERT INTO telemetry_suspicious_paths (
                    observed_at, path, source_type, source_name, reason
                ) VALUES (
                    $observedAt, $path, $sourceType, $sourceName, $reason
                );
                """,
                snapshot.ObservedAt);
            command.Parameters.AddWithValue("$path", item.Path);
            command.Parameters.AddWithValue("$sourceType", item.SourceType);
            command.Parameters.AddWithValue("$sourceName", item.SourceName);
            command.Parameters.AddWithValue("$reason", item.Reason);
            command.ExecuteNonQuery();
        }
    }

    private static SqliteCommand CreateCommand(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string sql,
        DateTimeOffset observedAt)
    {
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        command.Parameters.AddWithValue("$observedAt", ToSql(observedAt));
        return command;
    }
}
