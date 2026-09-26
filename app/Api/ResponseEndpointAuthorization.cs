using RoamSentinel.Core;
using RoamSentinel.App.Security;

namespace RoamSentinel.App.Api;

internal static class ResponseEndpointAuthorization
{
    public static IResult? Require(
        HttpContext context,
        ILocalSessionService sessions,
        string actionType,
        string target,
        string requiredRole = "Administrator")
    {
        var session = sessions.Resolve(context.Request);
        if (sessions.HasRole(session, requiredRole))
        {
            return null;
        }

        var error = $"{requiredRole} role is required.";
        context.RequestServices
            .GetRequiredService<IResponseActionRepository>()
            .Record(new ResponseActionRecord(
                Guid.NewGuid().ToString("N"),
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow,
                actionType,
                target,
                "denied",
                false,
                "",
                error,
                session?.Role ?? "anonymous"));
        return Results.Json(
            new ActionResultDto(false, "", error),
            statusCode: StatusCodes.Status403Forbidden);
    }
}
