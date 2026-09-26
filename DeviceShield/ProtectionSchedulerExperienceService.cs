using RoamSentinel.Config;
using RoamSentinel.Core;

namespace RoamSentinel.DeviceShield;

public sealed class ProtectionSchedulerExperienceService(
    IProtectionSchedulerRepository repository,
    SchedulerOptions options) : IProtectionSchedulerExperienceService
{
    private static readonly IReadOnlyDictionary<string, TaskOwnership> Ownership =
        new Dictionary<string, TaskOwnership>(StringComparer.OrdinalIgnoreCase)
        {
            ["telemetry-snapshot"] = new(
                "data-egress",
                "protect",
                "Data egress and process visibility"),
            ["app-activity"] = new(
                "app-activity",
                "protect",
                "Application behavior"),
            ["malware-posture"] = new(
                "malware-guard",
                "protect",
                "Malware posture"),
            ["quick-scan"] = new(
                "malware-guard",
                "protect",
                "Scheduled malware scan"),
            ["full-scan"] = new(
                "malware-guard",
                "protect",
                "Scheduled malware scan"),
            ["weekly-review"] = new(
                "protection-scheduler",
                "respond",
                "Operator review")
        };

    public SchedulerExperienceDashboardDto GetDashboard()
    {
        var dashboard = repository.GetDashboard(options.Enabled);
        var now = DateTimeOffset.UtcNow;
        var tasks = dashboard.Tasks.Select(task => Enrich(task, now)).ToList();
        var running = tasks.Count(task => task.DueState == "running");
        var failed = tasks.Count(task => task.DueState == "failed");
        var due = tasks.Count(task => task.DueState == "due");
        var disabled = tasks.Count(task => task.DueState == "disabled");
        var health = !dashboard.Enabled
            ? "disabled"
            : failed > 0
                ? "attention"
                : running > 0
                    ? "running"
                    : due > 0
                        ? "due"
                        : "healthy";

        return new SchedulerExperienceDashboardDto(
            dashboard.Enabled,
            dashboard.GeneratedAt,
            health,
            running,
            failed,
            due,
            disabled,
            tasks);
    }

    private static SchedulerTaskExperienceDto Enrich(
        SchedulerTaskStatusDto task,
        DateTimeOffset now)
    {
        var ownership = Ownership.TryGetValue(task.TaskKey, out var value)
            ? value
            : new TaskOwnership(
                "protection-scheduler",
                "admin",
                "Scheduler maintenance");
        var dueState = !task.Enabled
            ? "disabled"
            : task.LastStatus.Equals("running", StringComparison.OrdinalIgnoreCase)
                ? "running"
                : task.LastStatus.Equals("failed", StringComparison.OrdinalIgnoreCase)
                    ? "failed"
                    : task.NextRunAt is null || task.NextRunAt <= now
                        ? "due"
                        : "scheduled";

        return new SchedulerTaskExperienceDto(
            task.TaskKey,
            task.DisplayName,
            ownership.ModuleId,
            ownership.Workspace,
            ownership.Category,
            dueState,
            task.Enabled,
            task.IntervalSeconds,
            task.LastStartedAt,
            task.LastCompletedAt,
            task.NextRunAt,
            task.LastSuccess,
            task.LastStatus,
            task.LastMessage,
            task.SuccessCount,
            task.FailureCount);
    }

    private sealed record TaskOwnership(
        string ModuleId,
        string Workspace,
        string Category);
}
