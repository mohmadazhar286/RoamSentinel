using Microsoft.Win32;
using RoamSentinel.Config;
using RoamSentinel.Core;

namespace RoamSentinel.Telemetry;

public sealed class AgentInstallationCollector(
    IAgentIdentityService identities,
    TelemetryOptions telemetryOptions)
{
    private const string UninstallPath =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

    public IReadOnlyList<AgentInstallationTelemetry> Collect(
        IReadOnlyCollection<ProcessTelemetry> processes)
    {
        var items = new List<AgentInstallationTelemetry>();
        items.AddRange(processes
            .Where(process => identities.Identify(
                process.Name,
                process.Path,
                process.CommandLine).IsAgent)
            .Select(process => new AgentInstallationTelemetry(
                process.Name,
                process.Path,
                "",
                "",
                "Running process",
                true,
                process.ProcessId)));

        foreach (var hive in new[]
        {
            RegistryHive.LocalMachine,
            RegistryHive.CurrentUser
        })
        {
            foreach (var view in new[]
            {
                RegistryView.Registry64,
                RegistryView.Registry32
            })
            {
                ReadInstalledApplications(items, hive, view);
            }
        }

        return items
            .GroupBy(
                item => $"{item.Name}|{item.Path}|{item.ProcessId}",
                StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .OrderBy(item => item.Name)
            .ToList();
    }

    public IReadOnlyList<SuspiciousPathTelemetry> FindSuspiciousPaths(
        IReadOnlyCollection<ProcessTelemetry> processes,
        IReadOnlyCollection<StartupTelemetry> startupEntries,
        IReadOnlyCollection<ScheduledTaskTelemetry> scheduledTasks,
        IReadOnlyCollection<ServiceTelemetry> services,
        IReadOnlyCollection<AgentInstallationTelemetry> agents)
    {
        var candidates = processes
            .Select(item => (
                Path: item.Path,
                Type: "Process",
                Name: item.Name))
            .Concat(startupEntries.Select(
                item => (
                    Path: item.Command,
                    Type: "Startup",
                    Name: item.Name)))
            .Concat(scheduledTasks.Select(
                item => (
                    Path: $"{item.Command} {item.Arguments}".Trim(),
                    Type: "Scheduled task",
                    Name: item.Name)))
            .Concat(services.Select(
                item => (
                    Path: item.Path,
                    Type: "Service",
                    Name: item.Name)))
            .Concat(agents.Select(
                item => (
                    Path: item.Path,
                    Type: "AI agent",
                    Name: item.Name)));

        return candidates
            .Where(item => !string.IsNullOrWhiteSpace(item.Path))
            .Select(item =>
            {
                var marker = telemetryOptions.SuspiciousPathMarkers
                    .FirstOrDefault(value => item.Path.Contains(
                        value,
                        StringComparison.OrdinalIgnoreCase));
                return marker is null
                    ? null
                    : new SuspiciousPathTelemetry(
                        item.Path,
                        item.Type,
                        item.Name,
                        $"Path contains configured user-writable marker: {marker}");
            })
            .Where(item => item is not null)
            .Cast<SuspiciousPathTelemetry>()
            .DistinctBy(
                item => $"{item.Path}|{item.SourceType}|{item.SourceName}",
                StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private void ReadInstalledApplications(
        ICollection<AgentInstallationTelemetry> items,
        RegistryHive hive,
        RegistryView view)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, view);
            using var uninstall = baseKey.OpenSubKey(UninstallPath);
            if (uninstall is null)
            {
                return;
            }

            foreach (var subKeyName in uninstall.GetSubKeyNames())
            {
                using var key = uninstall.OpenSubKey(subKeyName);
                var name = key?.GetValue("DisplayName")?.ToString() ?? "";
                var location = key?.GetValue("InstallLocation")?.ToString() ?? "";
                var icon = key?.GetValue("DisplayIcon")?.ToString() ?? "";
                var path = string.IsNullOrWhiteSpace(location)
                    ? NormalizeDisplayIcon(icon)
                    : location;
                if (!identities.Identify(name, path).IsAgent)
                {
                    continue;
                }

                items.Add(new AgentInstallationTelemetry(
                    name,
                    path,
                    key?.GetValue("DisplayVersion")?.ToString() ?? "",
                    key?.GetValue("Publisher")?.ToString() ?? "",
                    $"Uninstall registry ({hive}/{view})",
                    false,
                    null));
            }
        }
        catch
        {
            // Continue with other registry hives and views.
        }
    }

    private static string NormalizeDisplayIcon(string value)
    {
        var path = value.Trim().Trim('"');
        var comma = path.LastIndexOf(',');
        return comma > 2 ? path[..comma].Trim().Trim('"') : path;
    }
}
