using RoamSentinel.Core;
using RoamSentinel.App.Security;

namespace RoamSentinel.App.Api;

public static class DevOpsEndpoints
{
    public static IEndpointRouteBuilder MapDevOpsEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/v1/devops/summary", GetDevHubSummaryAsync);
        endpoints.MapPost("/api/v1/devops/sync", TriggerSyncAsync);
        return endpoints;
    }

    private static async Task<IResult> GetDevHubSummaryAsync(
        IDevHubStatusService devHub,
        CancellationToken cancellationToken)
    {
        var summary = await devHub.GetSummaryAsync(cancellationToken);
        return Results.Ok(summary);
    }

    private static async Task<IResult> TriggerSyncAsync(
        SyncTriggerRequest request,
        IDevHubStatusService devHub,
        ILocalSessionService sessions,
        HttpContext context)
    {
        var denied = ResponseEndpointAuthorization.Require(
            context,
            sessions,
            "devops.sync",
            request.Action);
        if (denied is not null)
        {
            return denied;
        }

        var result = await devHub.TriggerSyncAsync(request.Action, context.RequestAborted);
        return Results.Ok(result);
    }

    public sealed record SyncTriggerRequest(string Action);
}
