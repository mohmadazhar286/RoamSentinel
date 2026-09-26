using RoamSentinel.App.Security;
using RoamSentinel.Core;

namespace RoamSentinel.App.Api;

public static class BackupEndpoints
{
    public static IEndpointRouteBuilder MapBackupEndpoints(
        this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/api/backup/export", Export);
        endpoints.MapPost("/api/backup/restore", Restore)
            .DisableAntiforgery();
        return endpoints;
    }

    private static IResult Export(
        IBackupExportService backups,
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

        var actor = sessions.Resolve(context.Request)?.Role ??
            "Administrator";
        var export = backups.Create(actor);
        return Results.File(
            export.Content,
            export.ContentType,
            export.FileName);
    }

    private static async Task<IResult> Restore(
        IBackupExportService backups,
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

        if (!context.Request.HasFormContentType)
        {
            return Results.BadRequest(new { error = "A backup ZIP file is required." });
        }

        var form = await context.Request.ReadFormAsync(context.RequestAborted);
        var file = form.Files.GetFile("backup");
        if (file is null || file.Length is <= 0 or > 1_073_741_824)
        {
            return Results.BadRequest(new { error = "Backup file size is invalid." });
        }

        try
        {
            await using var stream = file.OpenReadStream();
            var actor = sessions.Resolve(context.Request)?.Role ?? "Administrator";
            return Results.Ok(backups.Restore(stream, actor));
        }
        catch (InvalidDataException exception)
        {
            return Results.BadRequest(new { error = exception.Message });
        }
    }
}
