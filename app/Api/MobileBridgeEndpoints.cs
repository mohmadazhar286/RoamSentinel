using RoamSentinel.App.Security;
using RoamSentinel.Core;

namespace RoamSentinel.App.Api;

public static class MobileBridgeEndpoints
{
    public static IEndpointRouteBuilder MapMobileBridgeEndpoints(
        this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/mobile-bridge");
        group.MapGet("/", GetDashboard);
        group.MapPost("/pairing-sessions", CreatePairingSession);
        group.MapPost("/enroll", Enroll);
        group.MapPost("/heartbeat", RecordHeartbeat);
        group.MapPost("/app-inventory", RecordAppInventory);
        group.MapPost("/findings", RecordFindings);
        return endpoints;
    }

    private static IResult GetDashboard(IMobileBridgeService mobile) =>
        Results.Ok(mobile.GetDashboard());

    private static IResult CreatePairingSession(
        IMobileBridgeService mobile,
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

        var actor = sessions.Resolve(context.Request)?.Role ?? "Administrator";
        var session = mobile.CreatePairingSession(actor);
        var baseUrl = $"{context.Request.Scheme}://{context.Request.Host}";
        var payload =
            "rs://pair" +
            $"?c={Uri.EscapeDataString(session.PairingCode)}" +
            $"&b={Uri.EscapeDataString(baseUrl)}";
        return Results.Ok(session with
        {
            PairingPayload = payload,
            PairingScheme = "rs://pair",
            PairingBaseUrl = baseUrl
        });
    }

    private static IResult Enroll(
        MobileEnrollmentRequest request,
        IMobileBridgeService mobile) =>
        Guard(() => mobile.Enroll(request));

    private static IResult RecordHeartbeat(
        MobileHeartbeatRequest request,
        IMobileBridgeService mobile) =>
        Guard(() => mobile.RecordHeartbeat(request));

    private static IResult RecordAppInventory(
        MobileAppInventoryRequest request,
        IMobileBridgeService mobile) =>
        Guard(() =>
        {
            mobile.RecordAppInventory(request);
            return new { ok = true };
        });

    private static IResult RecordFindings(
        MobileFindingsRequest request,
        IMobileBridgeService mobile) =>
        Guard(() =>
        {
            mobile.RecordFindings(request);
            return new { ok = true };
        });

    private static IResult Guard<T>(Func<T> action)
    {
        try
        {
            return Results.Ok(action());
        }
        catch (UnauthorizedAccessException ex)
        {
            return Results.Json(
                new { error = ex.Message },
                statusCode: StatusCodes.Status401Unauthorized);
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }
}
