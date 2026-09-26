using RoamSentinel.App.Security;
using RoamSentinel.Core;

namespace RoamSentinel.App.Api;

public static class AuthenticationEndpoints
{
    public static IEndpointRouteBuilder MapAuthenticationEndpoints(
        this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet(
            "/api/auth/session",
            (ILocalSessionService sessions, HttpContext context) =>
                Results.Ok(sessions.GetSession(context.Request)));
        endpoints.MapPost("/api/auth/login", Login);
        endpoints.MapPost("/api/auth/logout", Logout);
        return endpoints;
    }

    private static IResult Login(
        LoginRequest request,
        ILocalSessionService sessions,
        HttpContext context)
    {
        if (string.IsNullOrWhiteSpace(request.Token) ||
            request.Token.Length > 512)
        {
            return Results.BadRequest(new
            {
                error = "A valid login token is required."
            });
        }

        try
        {
            return Results.Ok(sessions.Login(
                request.Token,
                context.Connection.RemoteIpAddress,
                context.Response));
        }
        catch (UnauthorizedAccessException ex)
        {
            return Results.Json(
                new { error = ex.Message },
                statusCode: StatusCodes.Status401Unauthorized);
        }
    }

    private static IResult Logout(
        ILocalSessionService sessions,
        HttpContext context)
    {
        var denied = EndpointSecurity.RequireRole(
            context,
            sessions,
            "Viewer");
        if (denied is not null)
        {
            return denied;
        }

        sessions.Logout(context.Request, context.Response);
        return Results.Ok(new { loggedOut = true });
    }
}
