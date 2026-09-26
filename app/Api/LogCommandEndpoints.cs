using RoamSentinel.Core;

namespace RoamSentinel.App.Api;

public static class LogCommandEndpoints
{
    public static IEndpointRouteBuilder MapLogCommandEndpoints(
        this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/api/logs/purge", PurgeLogs);
        return endpoints;
    }

    private static IResult PurgeLogs(
        IEventLogService eventLog,
        ILocalSessionService sessions,
        HttpContext context)
    {
        var denied = ResponseEndpointAuthorization.Require(
            context,
            sessions,
            "logs.purge",
            "reviewed-security-events");
        if (denied is not null)
        {
            return denied;
        }

        var count = eventLog.Purge();
        eventLog.RecordAction(
            "Logs purged after review",
            "Low",
            $"{count} logged event(s) were cleared.");
        return Results.Ok(new ActionResultDto(
            true,
            $"Purged {count} logged event(s).",
            ""));
    }
}
