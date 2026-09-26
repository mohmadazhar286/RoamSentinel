using System.Runtime.InteropServices;
using RoamSentinel.Config;
using RoamSentinel.Core;

namespace RoamSentinel.App.Queries;

public sealed class DashboardQueryService(
    ISecuritySnapshotService snapshots,
    IResourceMonitor resources,
    IDetectionEngine detection,
    IEventLogService eventLog,
    IEventRepository events,
    IMitreRepository mitre,
    IAgentGovernanceService governance,
    IThreatIntelService threatIntel,
    IThreatIndicatorRepository indicators,
    IResponseActionRepository responses,
    IAuditRepository audit,
    IDetectionRuleRepository detectionRules,
    IIpBlockRepository ipBlocks,
    IDatabaseStatusRepository database,
    IProtectionSchedulerRepository scheduler,
    ITelemetryService telemetry,
    RoamSentinelOptions hostOptions,
    DatabaseOptions databaseOptions,
    TelemetryOptions telemetryOptions,
    DetectionOptions detectionOptions,
    ResponseOptions responseOptions,
    AccessControlOptions accessControlOptions,
    AgentGovernanceOptions agentOptions,
    DashboardOptions dashboardOptions,
    SchedulerOptions schedulerOptions) : IDashboardQueryService
{
    public async Task<SecurityOverviewViewDto> GetSecurityOverviewAsync(
        CancellationToken cancellationToken = default)
    {
        var snapshot = await snapshots.CollectAsync(cancellationToken);
        var alerts = detection.BuildAlerts(snapshot.Detection);
        var summary = new SummaryDto(
            Environment.MachineName,
            RuntimeInformation.OSDescription,
            telemetry.IsAdministrator(),
            DateTimeOffset.Now,
            snapshot.Connections.Count,
            snapshot.Processes.Count,
            snapshot.StartupEntries.Count,
            snapshot.Defender,
            alerts.Count(item => item.Severity == "High"),
            alerts.Count(item => item.Severity == "Medium"),
            alerts.Count(item => item.Severity == "Low"),
            alerts.Count(item => item.Severity == "Critical"),
            alerts.Count(item => item.Severity == "Info"));
        return new SecurityOverviewViewDto(
            summary,
            BuildPerformance(snapshot),
            snapshot.Raw.Firewall,
            snapshot.Detection,
            snapshot.Raw.GovernedAgents?.Count ?? 0,
            database.GetStatus());
    }

    public async Task<IReadOnlyList<ProcessDto>> GetLiveProcessesAsync(
        CancellationToken cancellationToken = default) =>
        (await snapshots.CollectAsync(cancellationToken))
            .Processes
            .OrderByDescending(item => item.RiskScore)
            .ThenByDescending(item => item.MemoryMb)
            .ToList();

    public async Task<IReadOnlyList<ConnectionDto>>
        GetNetworkConnectionsAsync(
            CancellationToken cancellationToken = default) =>
        (await snapshots.CollectAsync(cancellationToken))
            .Connections
            .OrderByDescending(item => item.RiskScore)
            .ThenBy(item => item.ProcessName)
            .ToList();

    public async Task<IReadOnlyList<AlertDto>> GetAlertsAsync(
        CancellationToken cancellationToken = default)
    {
        await snapshots.CollectAsync(cancellationToken);
        return eventLog.GetRecent(dashboardOptions.EventReviewLimit)
            .Where(item => events.GetState(item.Id)?.Status == "open")
            .Take(100)
            .ToList();
    }

    public async Task<MitreDashboardViewDto> GetMitreAsync(
        CancellationToken cancellationToken = default)
    {
        await snapshots.CollectAsync(cancellationToken);
        return new MitreDashboardViewDto(
            DateTimeOffset.UtcNow,
            mitre.GetEvents(dashboardOptions.EventReviewLimit),
            mitre.GetTechniques());
    }

    public async Task<AgentViewDto> GetAgentsAsync(
        CancellationToken cancellationToken = default)
    {
        var snapshot = await snapshots.CollectAsync(cancellationToken);
        var policy = governance.GetPolicy();
        var agents = snapshot.Raw.GovernedAgents ??
            governance.GetRegistry();
        return new AgentViewDto(
            policy.AuthorizedPaths.OrderBy(path => path),
            policy.BlockedPaths.OrderBy(path => path),
            agents
                .OrderByDescending(item => item.IsRunning)
                .ThenByDescending(item => item.RiskScore)
                .ThenBy(item => item.Name));
    }

    public ThreatIntelDashboardViewDto GetThreatIntel() =>
        new(
            threatIntel.GetProviderStatus(),
            indicators.GetAll(dashboardOptions.EventReviewLimit));

    public IReadOnlyList<ResponseActionRecord> GetResponseHistory() =>
        responses.GetRecent(Math.Min(
            dashboardOptions.EventReviewLimit,
            200));

    public DashboardSettingsViewDto GetSettings()
    {
        var policy = governance.GetPolicy();
        return new DashboardSettingsViewDto(
            ProductInfo.Name,
            ProductInfo.Version,
            hostOptions.BindUrl,
            dashboardOptions.RefreshIntervalMilliseconds,
            telemetryOptions.CollectionIntervalSeconds,
            databaseOptions.TelemetryRetentionDays,
            agentOptions.ObservationPersistenceIntervalSeconds,
            detectionOptions.HighSeverityScore,
            detectionOptions.MediumSeverityScore,
            dashboardOptions.MemoryWarningPercent,
            dashboardOptions.MemoryDangerPercent,
            !string.IsNullOrWhiteSpace(
                accessControlOptions.AdministratorToken) ||
            !string.IsNullOrWhiteSpace(responseOptions.OperatorToken),
            responseOptions.CommandTimeoutSeconds,
            detectionRules.GetAll(),
            new PolicyReviewDto(
                policy.AuthorizedPaths.OrderBy(path => path),
                policy.BlockedPaths.OrderBy(path => path),
                ipBlocks.Load().OrderByDescending(item => item.BlockedAt),
                PolicyCatalog.ActivePolicies),
            database.GetStatus());
    }

    public IReadOnlyList<AuditLogEntryDto> GetAuditLog() =>
        audit.GetRecent(Math.Min(
            dashboardOptions.EventReviewLimit,
            200));

    public SchedulerDashboardDto GetScheduler() =>
        scheduler.GetDashboard(schedulerOptions.Enabled);

    private PerformanceDto BuildPerformance(SecuritySnapshot snapshot)
    {
        var memory = resources.GetMemory();
        return new PerformanceDto(
            DateTimeOffset.Now,
            memory,
            snapshot.Processes.Count,
            snapshot.Processes.Count(item =>
                item.MemoryMb >= dashboardOptions.HeavyMemoryThresholdMb),
            snapshot.Processes.Count(item =>
                item.CpuPercent >= dashboardOptions.HeavyCpuThresholdPercent),
            snapshot.Processes
                .OrderByDescending(item => item.MemoryMb)
                .Take(dashboardOptions.TopProcessLimit),
            snapshot.Processes
                .OrderByDescending(item => item.CpuPercent)
                .Take(dashboardOptions.TopProcessLimit));
    }
}
