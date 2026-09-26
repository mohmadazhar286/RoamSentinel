using System.Security.Cryptography;
using System.Text;
using RoamSentinel.Core;

namespace RoamSentinel.AppActivity;

public sealed class AppActivityService(
    IDeviceIntegrityInventoryService inventory,
    ITelemetryService telemetry,
    IAppActivityRepository repository,
    IStructuredLogService logs) : IAppActivityService
{
    public async Task<AppActivityDashboardDto> GetDashboardAsync(
        CancellationToken cancellationToken = default)
    {
        var connections = await telemetry.GetConnectionsAsync(cancellationToken);
        var processes = telemetry.GetProcesses(connections);
        var snapshot = await inventory.CollectAsync(cancellationToken);
        var observations = BuildObservations(snapshot, processes, connections);
        var dashboard = repository.RecordSnapshot(
            observations,
            DateTimeOffset.UtcNow);
        logs.App(
            "app_activity.dashboard.generated",
            "App activity snapshot generated.",
            new
            {
                dashboard.InstalledAppCount,
                dashboard.ActiveAppCount,
                dashboard.UnusedButActiveCount
            });
        return dashboard;
    }

    private static IReadOnlyList<AppActivityObservationDto> BuildObservations(
        DeviceIntegritySnapshot snapshot,
        IReadOnlyList<ProcessTelemetry> processes,
        IReadOnlyList<ConnectionTelemetry> connections)
    {
        var observedAt = DateTimeOffset.UtcNow;
        var networkByPid = connections
            .GroupBy(connection => connection.ProcessId)
            .ToDictionary(
                group => group.Key,
                group => group.Count());
        var autoStartSignals = snapshot.RegistryPersistence
            .Select(item => item.Value)
            .Concat(snapshot.ScheduledTasks.Select(item =>
                $"{item.Command} {item.Arguments}"))
            .Concat(snapshot.Services.Select(item => item.Path))
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .ToList();

        var observations = new List<AppActivityObservationDto>();
        foreach (var app in snapshot.InstalledSoftware)
        {
            if (string.IsNullOrWhiteSpace(app.Name))
            {
                continue;
            }

            var relatedProcesses = FindRelatedProcesses(app, processes);
            var processCount = relatedProcesses.Count;
            var connectionCount = relatedProcesses.Sum(process =>
                networkByPid.TryGetValue(process.ProcessId, out var count)
                    ? count
                    : 0);
            var autoStart = autoStartSignals.Any(signal =>
                MatchesApp(app, signal));
            observations.Add(new AppActivityObservationDto(
                AppId(app.Name, app.Publisher, app.InstallLocation),
                Clean(app.Name, 200),
                Clean(app.Publisher, 160),
                Clean(app.Version, 80),
                Clean(app.InstallLocation, 500),
                processCount > 0,
                processCount,
                connectionCount,
                autoStart,
                observedAt));
        }

        foreach (var process in processes.Where(process =>
            !string.IsNullOrWhiteSpace(process.Path) &&
            !observations.Any(app => PathBelongsToApp(process.Path, app))))
        {
            observations.Add(new AppActivityObservationDto(
                AppId(process.Name, "running-process", process.Path),
                Clean(process.Name, 200),
                "running-process",
                "",
                Clean(Path.GetDirectoryName(process.Path) ?? process.Path, 500),
                true,
                1,
                networkByPid.TryGetValue(process.ProcessId, out var count)
                    ? count
                    : 0,
                false,
                observedAt));
        }

        return observations
            .GroupBy(item => item.AppId)
            .Select(group => group.Aggregate((left, right) => left with
            {
                IsCurrentlyRunning = left.IsCurrentlyRunning || right.IsCurrentlyRunning,
                CurrentProcessCount =
                    left.CurrentProcessCount + right.CurrentProcessCount,
                CurrentNetworkConnectionCount =
                    left.CurrentNetworkConnectionCount +
                    right.CurrentNetworkConnectionCount,
                AutoStart = left.AutoStart || right.AutoStart
            }))
            .OrderBy(item => item.Name)
            .ToList();
    }

    private static List<ProcessTelemetry> FindRelatedProcesses(
        InstalledSoftwareTelemetry app,
        IReadOnlyList<ProcessTelemetry> processes) =>
        processes
            .Where(process =>
                !string.IsNullOrWhiteSpace(process.Path) &&
                MatchesApp(app, process.Path))
            .ToList();

    private static bool MatchesApp(
        InstalledSoftwareTelemetry app,
        string value)
    {
        var normalized = value.ToLowerInvariant();
        if (!string.IsNullOrWhiteSpace(app.InstallLocation) &&
            normalized.StartsWith(
                NormalizePath(app.InstallLocation).ToLowerInvariant(),
                StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var appName = NormalizeName(app.Name);
        return appName.Length >= 4 &&
            normalized.Contains(appName, StringComparison.OrdinalIgnoreCase);
    }

    private static bool PathBelongsToApp(
        string path,
        AppActivityObservationDto app)
    {
        if (!string.IsNullOrWhiteSpace(app.InstallLocation) &&
            NormalizePath(path).StartsWith(
                NormalizePath(app.InstallLocation),
                StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return NormalizePath(path).Contains(
            NormalizeName(app.Name),
            StringComparison.OrdinalIgnoreCase);
    }

    private static string AppId(
        string name,
        string publisher,
        string location)
    {
        var source = $"{name}|{publisher}|{location}".ToLowerInvariant();
        return Convert.ToHexString(SHA256.HashData(
            Encoding.UTF8.GetBytes(source)))[..24];
    }

    private static string NormalizePath(string path) =>
        path.Trim().Trim('"').Replace('/', '\\');

    private static string NormalizeName(string value) =>
        new(value
            .Where(char.IsLetterOrDigit)
            .Select(char.ToLowerInvariant)
            .ToArray());

    private static string Clean(string? value, int maxLength)
    {
        var clean = (value ?? string.Empty).Replace("\0", string.Empty).Trim();
        return clean.Length <= maxLength ? clean : clean[..maxLength];
    }
}
