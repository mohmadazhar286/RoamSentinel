using RoamSentinel.Core;

namespace RoamSentinel.Dashboard;

public static class DashboardSectionEndpoints
{
    public static IEndpointRouteBuilder MapDashboardSectionEndpoints(
        this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/dashboard");
        group.MapGet("/security-overview", GetSecurityOverviewAsync);
        group.MapGet("/live-processes", GetLiveProcessesAsync);
        group.MapGet("/network-connections", GetNetworkConnectionsAsync);
        group.MapGet("/alerts", GetAlertsAsync);
        group.MapGet("/mitre-attack", GetMitreAsync);
        group.MapGet("/ai-agent-governance", GetAgentsAsync);
        group.MapGet("/mobile-devices", GetMobileDevices);
        group.MapGet("/app-activity", GetAppActivityAsync);
        group.MapGet("/malware-guard", GetMalwareGuardAsync);
        group.MapGet("/threat-intel", GetThreatIntel);
        group.MapGet("/response-history", GetResponseHistory);
        group.MapGet("/settings", GetSettings);
        group.MapGet("/scheduler", GetScheduler);
        group.MapGet("/audit-log", GetAuditLog);
        return endpoints;
    }

    private static async Task<IResult> GetSecurityOverviewAsync(
        IDashboardQueryService queries,
        HttpContext context) =>
        Results.Ok(await queries.GetSecurityOverviewAsync(
            context.RequestAborted));

    private static async Task<IResult> GetLiveProcessesAsync(
        IDashboardQueryService queries,
        HttpContext context) =>
        Results.Ok(await queries.GetLiveProcessesAsync(
            context.RequestAborted));

    private static async Task<IResult> GetNetworkConnectionsAsync(
        IDashboardQueryService queries,
        HttpContext context) =>
        Results.Ok(await queries.GetNetworkConnectionsAsync(
            context.RequestAborted));

    private static async Task<IResult> GetAlertsAsync(
        IDashboardQueryService queries,
        HttpContext context) =>
        Results.Ok(await queries.GetAlertsAsync(context.RequestAborted));

    private static async Task<IResult> GetMitreAsync(
        IDashboardQueryService queries,
        HttpContext context) =>
        Results.Ok(await queries.GetMitreAsync(context.RequestAborted));

    private static async Task<IResult> GetAgentsAsync(
        IDashboardQueryService queries,
        HttpContext context) =>
        Results.Ok(await queries.GetAgentsAsync(context.RequestAborted));

    private static IResult GetMobileDevices(IMobileBridgeService mobile) =>
        Results.Ok(mobile.GetDashboard());

    private static async Task<IResult> GetAppActivityAsync(
        IAppActivityService appActivity,
        HttpContext context) =>
        Results.Ok(await appActivity.GetDashboardAsync(
            context.RequestAborted));

    private static async Task<IResult> GetMalwareGuardAsync(
        IMalwareGuardService malwareGuard,
        HttpContext context) =>
        Results.Ok(await malwareGuard.GetDashboardAsync(
            context.RequestAborted));

    private static IResult GetThreatIntel(IDashboardQueryService queries) =>
        Results.Ok(queries.GetThreatIntel());

    private static IResult GetResponseHistory(
        IDashboardQueryService queries) =>
        Results.Ok(queries.GetResponseHistory());

    private static IResult GetSettings(IDashboardQueryService queries) =>
        Results.Ok(queries.GetSettings());

    private static IResult GetScheduler(IDashboardQueryService queries) =>
        Results.Ok(queries.GetScheduler());

    private static IResult GetAuditLog(IDashboardQueryService queries) =>
        Results.Ok(queries.GetAuditLog());
}
