using RoamSentinel.Core;
using RoamSentinel.App.Security;

namespace RoamSentinel.App.Api;

public static class DeviceIntegrityEndpoints
{
    public static IEndpointRouteBuilder MapDeviceIntegrityEndpoints(
        this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet(
            "/api/v1/device-integrity",
            async (
                IDeviceIntegrityInventoryService inventory,
                HttpContext context) =>
                Results.Ok(await inventory.CollectAsync(
                    context.RequestAborted)));
        endpoints.MapGet(
            "/api/v1/device-integrity/events",
            (IDeviceIntegrityRepository repository, int? limit) =>
                Results.Ok(repository.GetRecentEvents(
                    Math.Clamp(limit ?? 100, 1, 500))));
        endpoints.MapGet(
            "/api/v1/device-integrity/findings",
            (IDeviceIntegrityFindingRepository repository, int? limit) =>
                Results.Ok(repository.GetRecent(
                    Math.Clamp(limit ?? 100, 1, 500))));
        endpoints.MapPost(
            "/api/v1/device-integrity/findings/{findingId}/status",
            (
                string findingId,
                DeviceIntegrityFindingStatusRequest request,
                IDeviceIntegrityFindingRepository repository,
                ILocalSessionService sessions,
                HttpContext context) =>
            {
                var denied = EndpointSecurity.RequireRole(
                    context,
                    sessions,
                    "Analyst");
                if (denied is not null)
                {
                    return denied;
                }

                if (findingId.Length > 128 ||
                    (request.Note?.Length ?? 0) > 500)
                {
                    return Results.BadRequest(new
                    {
                        error = "Device Integrity finding status input is invalid."
                    });
                }

                try
                {
                    var session = sessions.Resolve(context.Request);
                    var updated = repository.SetStatus(
                        findingId,
                        request.Status ?? "",
                        request.Note ?? "",
                        session?.Role ?? "local-user");
                    return updated is null
                        ? Results.NotFound()
                        : Results.Ok(updated);
                }
                catch (ArgumentException exception)
                {
                    return Results.BadRequest(new { error = exception.Message });
                }
            });
        return endpoints;
    }
}
