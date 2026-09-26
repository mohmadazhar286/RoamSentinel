using System.Runtime.InteropServices;
using RoamSentinel.Config;
using RoamSentinel.Core;

namespace RoamSentinel.App.Api;

public static class LegacyReadEndpoints
{
    public static IEndpointRouteBuilder MapLegacyReadEndpoints(
        this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/summary", GetSummaryAsync);
        endpoints.MapGet("/api/connections", GetConnectionsAsync);
        endpoints.MapGet("/api/processes", GetProcessesAsync);
        endpoints.MapGet("/api/performance", GetPerformanceAsync);
        endpoints.MapGet("/api/startup", GetStartupAsync);
        endpoints.MapGet("/api/defender", GetDefenderAsync);
        endpoints.MapGet("/api/firewall", GetFirewallAsync);
        endpoints.MapGet("/api/services", GetServicesAsync);
        endpoints.MapGet("/api/scheduled-tasks", GetScheduledTasksAsync);
        endpoints.MapGet("/api/installed-agents", GetInstalledAgentsAsync);
        endpoints.MapGet("/api/suspicious-paths", GetSuspiciousPathsAsync);
        endpoints.MapGet("/api/process-tree", GetProcessTreeAsync);
        endpoints.MapGet("/api/telemetry/snapshot", GetRawTelemetryAsync);
        endpoints.MapGet("/api/alerts", GetAlertsAsync);
        endpoints.MapGet("/api/detections", GetDetectionsAsync);
        endpoints.MapGet("/api/detection/rules", GetDetectionRules);
        endpoints.MapGet("/api/mitre/events", GetMitreEventsAsync);
        endpoints.MapGet("/api/mitre/techniques", GetMitreTechniques);
        endpoints.MapGet(
            "/api/threat-intel/providers",
            GetThreatIntelProviders);
        endpoints.MapGet(
            "/api/threat-intel/iocs",
            GetThreatIndicators);
        endpoints.MapGet("/api/logs", GetLogs);
        endpoints.MapGet("/api/audit", GetAudit);
        endpoints.MapGet("/api/response/actions", GetResponseActions);
        endpoints.MapGet("/api/config", GetDashboardConfig);
        endpoints.MapGet("/api/database/status", GetDatabaseStatus);
        endpoints.MapGet("/api/policies", GetPolicies);
        endpoints.MapGet("/api/agents", GetAgentsAsync);
        endpoints.MapGet("/api/agents/catalog", GetAgentCatalog);
        return endpoints;
    }

    private static async Task<IResult> GetSummaryAsync(
        ISecuritySnapshotService snapshots,
        IDetectionEngine detection,
        IEventLogService eventLog,
        ITelemetryService telemetry,
        HttpContext context)
    {
        var snapshot = await snapshots.CollectAsync(context.RequestAborted);
        var alerts = detection.BuildAlerts(snapshot.Detection);
        eventLog.RecordAlerts(alerts);

        return Results.Ok(new SummaryDto(
            Environment.MachineName,
            RuntimeInformation.OSDescription,
            telemetry.IsAdministrator(),
            DateTimeOffset.Now,
            snapshot.Connections.Count,
            snapshot.Processes.Count,
            snapshot.StartupEntries.Count,
            snapshot.Defender,
            alerts.Count(alert => alert.Severity == "High"),
            alerts.Count(alert => alert.Severity == "Medium"),
            alerts.Count(alert => alert.Severity == "Low"),
            alerts.Count(alert => alert.Severity == "Critical"),
            alerts.Count(alert => alert.Severity == "Info")));
    }

    private static async Task<IResult> GetConnectionsAsync(
        ISecuritySnapshotService snapshots,
        HttpContext context)
    {
        var snapshot = await snapshots.CollectAsync(context.RequestAborted);
        return Results.Ok(snapshot.Connections
            .OrderByDescending(connection => connection.RiskScore)
            .ThenBy(connection => connection.ProcessName));
    }

    private static async Task<IResult> GetProcessesAsync(
        ISecuritySnapshotService snapshots,
        HttpContext context)
    {
        var snapshot = await snapshots.CollectAsync(context.RequestAborted);
        return Results.Ok(snapshot.Processes
            .OrderByDescending(process => process.RiskScore)
            .ThenByDescending(process => process.MemoryMb));
    }

    private static async Task<IResult> GetPerformanceAsync(
        ISecuritySnapshotService snapshots,
        IResourceMonitor resources,
        DashboardOptions options,
        HttpContext context)
    {
        var snapshot = await snapshots.CollectAsync(context.RequestAborted);
        var memory = resources.GetMemory();
        return Results.Ok(new PerformanceDto(
            DateTimeOffset.Now,
            memory,
            snapshot.Processes.Count,
            snapshot.Processes.Count(process =>
                process.MemoryMb >= options.HeavyMemoryThresholdMb),
            snapshot.Processes.Count(process =>
                process.CpuPercent >= options.HeavyCpuThresholdPercent),
            snapshot.Processes
                .OrderByDescending(process => process.MemoryMb)
                .Take(options.TopProcessLimit),
            snapshot.Processes
                .OrderByDescending(process => process.CpuPercent)
                .Take(options.TopProcessLimit)));
    }

    private static async Task<IResult> GetStartupAsync(
        ISecuritySnapshotService snapshots,
        HttpContext context)
    {
        var snapshot = await snapshots.CollectAsync(context.RequestAborted);
        return Results.Ok(snapshot.StartupEntries);
    }

    private static async Task<IResult> GetDefenderAsync(
        ISecuritySnapshotService snapshots,
        HttpContext context) =>
        Results.Ok((await snapshots.CollectAsync(context.RequestAborted))
            .Raw.Defender);

    private static async Task<IResult> GetFirewallAsync(
        ISecuritySnapshotService snapshots,
        HttpContext context) =>
        Results.Ok((await snapshots.CollectAsync(context.RequestAborted))
            .Raw.Firewall);

    private static async Task<IResult> GetServicesAsync(
        ISecuritySnapshotService snapshots,
        HttpContext context) =>
        Results.Ok((await snapshots.CollectAsync(context.RequestAborted))
            .Raw.Services
            .OrderBy(service => service.Name));

    private static async Task<IResult> GetScheduledTasksAsync(
        ISecuritySnapshotService snapshots,
        HttpContext context) =>
        Results.Ok((await snapshots.CollectAsync(context.RequestAborted))
            .Raw.ScheduledTasks
            .OrderBy(task => task.Path)
            .ThenBy(task => task.Name));

    private static async Task<IResult> GetInstalledAgentsAsync(
        ISecuritySnapshotService snapshots,
        HttpContext context) =>
        Results.Ok((await snapshots.CollectAsync(context.RequestAborted))
            .Raw.InstalledAgents);

    private static async Task<IResult> GetSuspiciousPathsAsync(
        ISecuritySnapshotService snapshots,
        HttpContext context) =>
        Results.Ok((await snapshots.CollectAsync(context.RequestAborted))
            .Raw.SuspiciousPaths);

    private static async Task<IResult> GetProcessTreeAsync(
        ISecuritySnapshotService snapshots,
        HttpContext context) =>
        Results.Ok((await snapshots.CollectAsync(context.RequestAborted))
            .Raw.Processes
            .Select(process => new
            {
                process.ProcessId,
                process.Name,
                process.Path,
                process.ParentProcessId,
                process.ParentProcessName,
                process.CommandLine
            })
            .OrderBy(process => process.ParentProcessId)
            .ThenBy(process => process.ProcessId));

    private static async Task<IResult> GetRawTelemetryAsync(
        ISecuritySnapshotService snapshots,
        HttpContext context) =>
        Results.Ok((await snapshots.CollectAsync(context.RequestAborted)).Raw);

    private static async Task<IResult> GetAlertsAsync(
        ISecuritySnapshotService snapshots,
        IDetectionEngine detection,
        IEventLogService eventLog,
        IEventRepository events,
        HttpContext context)
    {
        var snapshot = await snapshots.CollectAsync(context.RequestAborted);
        var alerts = detection.BuildAlerts(snapshot.Detection);
        eventLog.RecordAlerts(alerts);
        return Results.Ok(eventLog.GetRecent()
            .Where(alert => events.GetState(alert.Id)?.Status == "open")
            .Take(30));
    }

    private static async Task<IResult> GetDetectionsAsync(
        ISecuritySnapshotService snapshots,
        HttpContext context) =>
        Results.Ok((await snapshots.CollectAsync(context.RequestAborted))
            .Detection);

    private static IResult GetDetectionRules(
        IDetectionRuleRepository rules) =>
        Results.Ok(rules.GetAll());

    private static async Task<IResult> GetMitreEventsAsync(
        ISecuritySnapshotService snapshots,
        IMitreRepository mitre,
        HttpContext context)
    {
        await snapshots.CollectAsync(context.RequestAborted);
        var query = context.Request.Query;
        var tactic = query["tactic"].ToString();
        var technique = query["technique"].ToString();
        var severity = query["severity"].ToString();
        var host = query["host"].ToString();
        var from = DateTimeOffset.TryParse(
            query["from"],
            out var parsedFrom)
            ? parsedFrom
            : (DateTimeOffset?)null;
        var to = DateTimeOffset.TryParse(
            query["to"],
            out var parsedTo)
            ? parsedTo
            : (DateTimeOffset?)null;
        var limit = int.TryParse(query["limit"], out var requestedLimit)
            ? requestedLimit
            : 2000;
        var events = mitre.GetEvents(limit)
            .Where(item => Matches(item.Tactic, tactic))
            .Where(item => Matches(item.TechniqueId, technique))
            .Where(item => Matches(item.Severity, severity))
            .Where(item => Matches(item.Host, host))
            .Where(item => from is null || item.LastSeenAt >= from)
            .Where(item => to is null || item.LastSeenAt <= to)
            .ToList();

        return Results.Ok(new
        {
            generatedAt = DateTimeOffset.UtcNow,
            events,
            facets = new
            {
                tactics = events
                    .GroupBy(item => item.Tactic)
                    .Select(group => new
                    {
                        name = group.Key,
                        count = group.Count()
                    })
                    .OrderByDescending(item => item.count),
                techniques = events
                    .GroupBy(item => new
                    {
                        item.TechniqueId,
                        item.TechniqueName
                    })
                    .Select(group => new
                    {
                        id = group.Key.TechniqueId,
                        name = group.Key.TechniqueName,
                        count = group.Count()
                    })
                    .OrderByDescending(item => item.count),
                severities = events
                    .GroupBy(item => item.Severity)
                    .Select(group => new
                    {
                        name = group.Key,
                        count = group.Count()
                    }),
                hosts = events
                    .GroupBy(item => item.Host)
                    .Select(group => new
                    {
                        name = group.Key,
                        count = group.Count()
                    })
            }
        });
    }

    private static IResult GetMitreTechniques(IMitreRepository mitre) =>
        Results.Ok(mitre.GetTechniques());

    private static IResult GetThreatIntelProviders(
        IThreatIntelService threatIntel) =>
        Results.Ok(threatIntel.GetProviderStatus());

    private static IResult GetThreatIndicators(
        IThreatIndicatorRepository indicators,
        DashboardOptions options) =>
        Results.Ok(indicators.GetAll(options.EventReviewLimit));

    private static bool Matches(string value, string filter) =>
        string.IsNullOrWhiteSpace(filter) ||
        string.Equals(value, filter, StringComparison.OrdinalIgnoreCase);

    private static IResult GetLogs(
        IEventLogService eventLog,
        DashboardOptions options) =>
        Results.Ok(eventLog.GetRecent(options.EventReviewLimit));

    private static IResult GetAudit(
        IAuditRepository audit,
        DashboardOptions options) =>
        Results.Ok(audit.GetRecent(options.EventReviewLimit));

    private static IResult GetResponseActions(
        IResponseActionRepository actions,
        DashboardOptions options) =>
        Results.Ok(actions.GetRecent(options.EventReviewLimit));

    private static IResult GetDashboardConfig(
        DashboardOptions options,
        DetectionOptions detection) =>
        Results.Ok(new
        {
            refreshIntervalMilliseconds =
                options.RefreshIntervalMilliseconds,
            memoryWarningPercent = options.MemoryWarningPercent,
            memoryDangerPercent = options.MemoryDangerPercent,
            highRiskScore = detection.HighSeverityScore,
            mediumRiskScore = detection.MediumSeverityScore
        });

    private static IResult GetDatabaseStatus(
        IDatabaseStatusRepository database) =>
        Results.Ok(database.GetStatus());

    private static IResult GetPolicies(
        IAgentGovernanceService governance,
        IIpBlockRepository ipBlocks)
    {
        var policy = governance.GetPolicy();
        return Results.Ok(new PolicyReviewDto(
            policy.AuthorizedPaths.OrderBy(path => path),
            policy.BlockedPaths.OrderBy(path => path),
            ipBlocks.Load().OrderByDescending(block => block.BlockedAt),
            PolicyCatalog.ActivePolicies));
    }

    private static async Task<IResult> GetAgentsAsync(
        ISecuritySnapshotService snapshots,
        IAgentGovernanceService governance,
        HttpContext context)
    {
        var snapshot = await snapshots.CollectAsync(context.RequestAborted);
        var agents = snapshot.Raw.GovernedAgents ??
            governance.GetRegistry();
        var policy = governance.GetPolicy();

        return Results.Ok(new AgentViewDto(
            policy.AuthorizedPaths.OrderBy(path => path),
            policy.BlockedPaths.OrderBy(path => path),
            agents
                .OrderByDescending(agent => agent.IsRunning)
                .ThenByDescending(agent => agent.RiskScore)
                .ThenBy(agent => agent.Name)));
    }

    private static IResult GetAgentCatalog(
        IAgentRegistryRepository agents) =>
        Results.Ok(agents.GetDefinitions());
}
