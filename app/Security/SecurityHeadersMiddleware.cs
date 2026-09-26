namespace RoamSentinel.App.Security;

public sealed class SecurityHeadersMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context)
    {
        context.Response.OnStarting(() =>
        {
            var headers = context.Response.Headers;
            headers.XContentTypeOptions = "nosniff";
            headers.XFrameOptions = "DENY";
            headers["Referrer-Policy"] = "no-referrer";
            headers["Permissions-Policy"] =
                "camera=(), microphone=(), geolocation=()";
            headers.ContentSecurityPolicy =
                "default-src 'self'; object-src 'none'; base-uri 'none'; " +
                "frame-ancestors 'none'; form-action 'self'; " +
                "script-src 'self'; style-src 'self' 'unsafe-inline'";
            if (context.Request.Path.StartsWithSegments("/api"))
            {
                headers.CacheControl = "no-store";
            }

            return Task.CompletedTask;
        });
        await next(context);
    }
}
