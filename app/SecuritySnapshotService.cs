using RoamSentinel.Core;

namespace RoamSentinel.App;

public sealed class SecuritySnapshotService(
    ITelemetryService telemetry,
    ITelemetryRepository telemetryRepository,
    IDetectionEngine detection,
    IMitreRepository mitre,
    IAgentGovernanceService governance,
    IEventLogService eventLog,
    Config.TelemetryOptions telemetryOptions,
    Config.DetectionOptions detectionOptions) : ISecuritySnapshotService
{
    private readonly SemaphoreSlim _collectionGate = new(1, 1);
    private SecuritySnapshot? _cached;
    private DateTimeOffset _cachedAt = DateTimeOffset.MinValue;

    public async Task<SecuritySnapshot> CollectAsync(
        CancellationToken cancellationToken = default)
    {
        var cached = GetFreshCache();
        if (cached is not null)
        {
            return cached;
        }

        await _collectionGate.WaitAsync(cancellationToken);
        try
        {
            cached = GetFreshCache();
            if (cached is not null)
            {
                return cached;
            }

            _cached = await CollectCoreAsync(cancellationToken);
            _cachedAt = DateTimeOffset.UtcNow;
            return _cached;
        }
        finally
        {
            _collectionGate.Release();
        }
    }

    private async Task<SecuritySnapshot> CollectCoreAsync(
        CancellationToken cancellationToken)
    {
        var connectionsTask = telemetry.GetConnectionsAsync(cancellationToken);
        var processMetadataTask =
            telemetry.GetProcessMetadataAsync(cancellationToken);
        var scheduledTasksTask =
            telemetry.GetScheduledTasksAsync(cancellationToken);
        var servicesTask = telemetry.GetServicesAsync(cancellationToken);
        var defenderTask = telemetry.GetDefenderStatusAsync(cancellationToken);
        var firewallTask = telemetry.GetFirewallStatusAsync(cancellationToken);
        await Task.WhenAll(
            connectionsTask,
            processMetadataTask,
            scheduledTasksTask,
            servicesTask,
            defenderTask,
            firewallTask);

        var rawConnections = await connectionsTask;
        var processMetadata = await processMetadataTask;
        var collectedProcesses = telemetry.GetProcesses(rawConnections);
        var processNames = collectedProcesses.ToDictionary(
            process => process.ProcessId,
            process => process.Name);
        var rawProcesses = collectedProcesses
            .Select(process =>
            {
                if (!processMetadata.TryGetValue(
                    process.ProcessId,
                    out var metadata))
                {
                    return process;
                }

                return process with
                {
                    ParentProcessId = metadata.ParentProcessId,
                    ParentProcessName = processNames.GetValueOrDefault(
                        metadata.ParentProcessId) ?? "",
                    CommandLine = metadata.CommandLine
                };
            })
            .ToList();
        var scheduledTasks = await scheduledTasksTask;
        var services = await servicesTask;
        var rawStartupEntries = telemetry.GetStartupEntries()
            .Concat(scheduledTasks.Select(task => new StartupTelemetry(
                task.Name,
                $"{task.Command} {task.Arguments}".Trim(),
                "Scheduled task")))
            .Concat(services
                .Where(service => string.Equals(
                    service.StartMode,
                    "Auto",
                    StringComparison.OrdinalIgnoreCase))
                .Select(service => new StartupTelemetry(
                    service.Name,
                    service.Path,
                    "Auto-start service")))
            .ToList();
        var defender = await defenderTask;
        var firewall = await firewallTask;
        var installedAgents = telemetry.GetInstalledAgents(rawProcesses);
        var suspiciousPaths = telemetry.GetSuspiciousPaths(
            rawProcesses,
            rawStartupEntries,
            scheduledTasks,
            services,
            installedAgents);
        var raw = new TelemetrySnapshot(
            DateTimeOffset.UtcNow,
            rawConnections,
            rawProcesses,
            rawStartupEntries,
            scheduledTasks,
            services,
            defender,
            firewall,
            installedAgents,
            suspiciousPaths);
        telemetryRepository.PersistSnapshot(raw);
        var governedAgents = governance.Observe(raw);
        raw = raw with { GovernedAgents = governedAgents };

        var detectionResult = detection.Evaluate(
            raw,
            governance.GetPolicy());
        eventLog.RecordAlerts(detection.BuildAlerts(detectionResult));
        mitre.PersistFindings(detectionResult, Environment.MachineName);
        var connections = rawConnections
            .Select(connection => detection.AssessConnection(
                connection,
                detectionResult))
            .ToList();
        var processes = rawProcesses
            .Select(process => detection.AssessProcess(
                process,
                governance.Evaluate(process, rawConnections),
                detectionResult))
            .ToList();
        var startupEntries = rawStartupEntries
            .Select(startup => detection.AssessStartup(
                startup,
                detectionResult))
            .Where(ShouldDisplayStartupEntry)
            .ToList();

        return new SecuritySnapshot(
            connections,
            processes,
            startupEntries,
            defender,
            raw,
            detectionResult);
    }

    private SecuritySnapshot? GetFreshCache() =>
        _cached is not null &&
        DateTimeOffset.UtcNow - _cachedAt <
            TimeSpan.FromSeconds(telemetryOptions.CollectionIntervalSeconds)
            ? _cached
            : null;

    private bool ShouldDisplayStartupEntry(StartupEntryDto entry) =>
        entry.Source is not "Auto-start service" and not "Scheduled task" ||
        entry.RiskScore >= detectionOptions.StartupAlertMinimumScore;
}
