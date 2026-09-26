using RoamSentinel.Config;
using RoamSentinel.Core;

namespace RoamSentinel.DeviceShield;

public sealed class ProtectionSchedulerService(
    ISecuritySnapshotService snapshots,
    IAppActivityService appActivity,
    IMalwareGuardService malwareGuard,
    IResponseService responses,
    IEventLogService eventLog,
    IProtectionSchedulerRepository repository,
    IStructuredLogService logs,
    SchedulerOptions options) : BackgroundService
{
    private readonly IReadOnlyList<ScheduledProtectionTask> _tasks =
    [
        new(
            "telemetry-snapshot",
            "Data egress and process snapshot",
            options.TelemetrySnapshotIntervalSeconds,
            true,
            async token =>
            {
                var snapshot = await snapshots.CollectAsync(token);
                return $"Observed {snapshot.Connections.Count} outbound flow(s), " +
                    $"{snapshot.Processes.Count} process(es), " +
                    $"{snapshot.Detection.Findings.Count} finding(s).";
            }),
        new(
            "app-activity",
            "App activity intelligence",
            options.AppActivityIntervalSeconds,
            true,
            async token =>
            {
                var dashboard = await appActivity.GetDashboardAsync(token);
                return $"Indexed {dashboard.InstalledAppCount} app(s); " +
                    $"{dashboard.ActiveAppCount} active, " +
                    $"{dashboard.UnusedButActiveCount} unused-but-active.";
            }),
        new(
            "malware-posture",
            "Malware posture and suspicious files",
            options.MalwarePostureIntervalSeconds,
            true,
            async token =>
            {
                var dashboard = await malwareGuard.GetDashboardAsync(token);
                return $"Malware posture checked; " +
                    $"{dashboard.RecentDetections.Count} Defender history item(s), " +
                    $"{dashboard.SuspiciousFiles.Count} suspicious file observation(s).";
            }),
        new(
            "quick-scan",
            "Scheduled malware quick scan",
            (int)TimeSpan.FromHours(options.QuickScanIntervalHours).TotalSeconds,
            options.EnableScheduledQuickScan,
            async token =>
            {
                var result = await responses.StartDefenderScanAsync("quick", token);
                if (!result.Ok)
                {
                    throw new InvalidOperationException(result.Error);
                }

                return result.Output;
            }),
        new(
            "full-scan",
            "Scheduled malware full scan",
            (int)TimeSpan.FromDays(options.FullScanIntervalDays).TotalSeconds,
            options.EnableScheduledFullScan,
            async token =>
            {
                var result = await responses.StartDefenderScanAsync("full", token);
                if (!result.Ok)
                {
                    throw new InvalidOperationException(result.Error);
                }

                return result.Output;
            }),
        new(
            "weekly-review",
            "Weekly protection review reminder",
            (int)TimeSpan.FromDays(options.WeeklyReviewIntervalDays).TotalSeconds,
            true,
            _ =>
            {
                eventLog.RecordAction(
                    "Protection review due",
                    "Info",
                    "Review alerts, app data activity, blocked policies, " +
                    "mobile devices, and audit log before purging reviewed items.");
                return Task.FromResult("Weekly review reminder recorded.");
            })
    ];

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        repository.EnsureTasks(BuildInitialStatuses(DateTimeOffset.UtcNow));
        if (!options.Enabled)
        {
            logs.App(
                "scheduler.disabled",
                "Protection scheduler is disabled by configuration.");
            return;
        }

        logs.App(
            "scheduler.started",
            "Protection scheduler started.",
            new { TaskCount = _tasks.Count });
        await RunDueTasksAsync(stoppingToken);
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(
            options.LoopIntervalSeconds));
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            await RunDueTasksAsync(stoppingToken);
        }
    }

    private async Task RunDueTasksAsync(CancellationToken stoppingToken)
    {
        var dashboard = repository.GetDashboard(options.Enabled);
        var dueTasks = dashboard.Tasks
            .Where(task =>
                task.Enabled &&
                (task.NextRunAt is null ||
                 task.NextRunAt <= DateTimeOffset.UtcNow))
            .ToList();
        foreach (var taskStatus in dueTasks)
        {
            var task = _tasks.FirstOrDefault(item =>
                string.Equals(
                    item.TaskKey,
                    taskStatus.TaskKey,
                    StringComparison.OrdinalIgnoreCase));
            if (task is null)
            {
                continue;
            }

            await RunTaskAsync(task, stoppingToken);
        }
    }

    private async Task RunTaskAsync(
        ScheduledProtectionTask task,
        CancellationToken stoppingToken)
    {
        var startedAt = DateTimeOffset.UtcNow;
        repository.MarkStarted(task.TaskKey, startedAt);
        try
        {
            var message = await task.Execute(stoppingToken);
            var completedAt = DateTimeOffset.UtcNow;
            repository.MarkCompleted(
                task.TaskKey,
                completedAt,
                true,
                "ok",
                message,
                completedAt.AddSeconds(task.IntervalSeconds));
            logs.App(
                "scheduler.task.completed",
                task.DisplayName,
                new { task.TaskKey, Message = message });
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            var completedAt = DateTimeOffset.UtcNow;
            repository.MarkCompleted(
                task.TaskKey,
                completedAt,
                false,
                "failed",
                exception.Message,
                completedAt.AddSeconds(task.IntervalSeconds));
            logs.Error(
                "scheduler.task.failed",
                exception,
                new { task.TaskKey, task.DisplayName });
        }
    }

    private IReadOnlyCollection<SchedulerTaskStatusDto> BuildInitialStatuses(
        DateTimeOffset now) =>
        _tasks.Select(task => new SchedulerTaskStatusDto(
            task.TaskKey,
            task.DisplayName,
            task.Enabled,
            task.IntervalSeconds,
            null,
            null,
            now,
            false,
            "pending",
            "",
            0,
            0)).ToList();

    private sealed record ScheduledProtectionTask(
        string TaskKey,
        string DisplayName,
        int IntervalSeconds,
        bool Enabled,
        Func<CancellationToken, Task<string>> Execute);
}
