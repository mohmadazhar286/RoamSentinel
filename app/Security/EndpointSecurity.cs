using RoamSentinel.Core;

namespace RoamSentinel.App.Security;

public static class EndpointSecurity
{
    public static IResult? RequireRole(
        HttpContext context,
        ILocalSessionService sessions,
        string role)
    {
        var session = sessions.Resolve(context.Request);
        return sessions.HasRole(session, role)
            ? null
            : Results.Json(
                new { error = $"{role} role is required." },
                statusCode: StatusCodes.Status403Forbidden);
    }
}
