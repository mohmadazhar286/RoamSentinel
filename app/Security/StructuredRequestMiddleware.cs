using RoamSentinel.Core;

namespace RoamSentinel.App.Security;

public sealed class StructuredRequestMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(
        HttpContext context,
        IStructuredLogService logs)
    {
        try
        {
            await next(context);
            if (context.Request.Path.StartsWithSegments("/api") &&
                context.Request.Method is
                    "POST" or "PUT" or "PATCH" or "DELETE")
            {
                logs.App(
                    "api.write",
                    "API write request completed.",
                    new
                    {
                        context.Request.Method,
                        Path = context.Request.Path.ToString(),
                        context.Response.StatusCode,
                        RemoteAddress =
                            context.Connection.RemoteIpAddress?.ToString() ??
                            "unknown"
                    });
            }
        }
        catch (Exception ex)
        {
            logs.Error(
                "request.unhandled_exception",
                ex,
                new
                {
                    context.Request.Method,
                    Path = context.Request.Path.ToString(),
                    RemoteAddress =
                        context.Connection.RemoteIpAddress?.ToString() ??
                        "unknown"
                });
            if (!context.Response.HasStarted)
            {
                context.Response.StatusCode =
                    StatusCodes.Status500InternalServerError;
                await context.Response.WriteAsJsonAsync(new
                {
                    error = "An internal error occurred."
                });
                return;
            }

            throw;
        }
    }
}
