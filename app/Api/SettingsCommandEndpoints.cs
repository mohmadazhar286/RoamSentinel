using RoamSentinel.App.Security;
using RoamSentinel.Core;

namespace RoamSentinel.App.Api;

public static class SettingsCommandEndpoints
{
    public static IEndpointRouteBuilder MapSettingsCommandEndpoints(
        this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/api/settings/{key}", Set);
        return endpoints;
    }

    private static IResult Set(
        string key,
        SettingChangeRequest request,
        ISystemSettingsRepository settings,
        ILocalSessionService sessions,
        HttpContext context)
    {
        var denied = EndpointSecurity.RequireRole(
            context,
            sessions,
            "Administrator");
        if (denied is not null)
        {
            return denied;
        }

        if (string.IsNullOrWhiteSpace(key) ||
            key.Length > 64 ||
            string.IsNullOrWhiteSpace(request.Value) ||
            request.Value.Length > 16)
        {
            return Results.BadRequest(new { error = "Invalid setting." });
        }

        try
        {
            var actor = sessions.Resolve(context.Request)?.Role ??
                "Administrator";
            return Results.Ok(settings.Set(key, request.Value, actor));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }
}
