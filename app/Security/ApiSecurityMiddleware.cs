using RoamSentinel.Config;
using RoamSentinel.Core;

namespace RoamSentinel.App.Security;

public sealed class ApiSecurityMiddleware(
    RequestDelegate next,
    AccessControlOptions options)
{
    public async Task InvokeAsync(
        HttpContext context,
        ILocalSessionService sessions,
        IStructuredLogService logs)
    {
        if (IsWriteRequest(context.Request) &&
            !string.Equals(
                context.Request.Path.Value,
                "/api/auth/login",
                StringComparison.OrdinalIgnoreCase) &&
            !IsMobileDeviceIngest(context.Request))
        {
            var session = sessions.Resolve(context.Request);
            if (session is null)
            {
                await Reject(
                    context,
                    logs,
                    StatusCodes.Status401Unauthorized,
                    "Authentication is required.");
                return;
            }

            var csrf = context.Request.Headers[options.CsrfHeaderName]
                .FirstOrDefault();
            if (!sessions.ValidateCsrf(session, csrf))
            {
                await Reject(
                    context,
                    logs,
                    StatusCodes.Status403Forbidden,
                    "CSRF validation failed.");
                return;
            }
        }

        await next(context);
    }

    private static bool IsWriteRequest(HttpRequest request) =>
        request.Path.StartsWithSegments("/api") &&
        request.Method is "POST" or "PUT" or "PATCH" or "DELETE";

    private static bool IsMobileDeviceIngest(HttpRequest request)
    {
        var path = request.Path.Value ?? string.Empty;
        return string.Equals(path, "/api/mobile-bridge/enroll", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(path, "/api/mobile-bridge/heartbeat", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(path, "/api/mobile-bridge/app-inventory", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(path, "/api/mobile-bridge/findings", StringComparison.OrdinalIgnoreCase);
    }

    private static async Task Reject(
        HttpContext context,
        IStructuredLogService logs,
        int statusCode,
        string message)
    {
        logs.Security(
            "request.rejected",
            message,
            new
            {
                context.Request.Method,
                Path = context.Request.Path.ToString(),
                RemoteAddress =
                    context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                StatusCode = statusCode
            });
        context.Response.StatusCode = statusCode;
        await context.Response.WriteAsJsonAsync(new { error = message });
    }
}
