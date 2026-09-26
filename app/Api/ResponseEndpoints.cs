using RoamSentinel.App.Security;
using RoamSentinel.Core;

namespace RoamSentinel.App.Api;

public static class ResponseEndpoints
{
    public static IEndpointRouteBuilder MapResponseEndpoints(
        this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/api/actions/scan", StartScanAsync);
        endpoints.MapPost("/api/actions/block-ip", BlockIpAsync);
        endpoints.MapPost("/api/actions/unblock-ip", UnblockIpAsync);
        endpoints.MapPost("/api/actions/kill-process", KillProcess);
        endpoints.MapPost("/api/actions/quarantine-file", QuarantineFileAsync);
        endpoints.MapPost("/api/actions/disable-startup", DisableStartupAsync);
        endpoints.MapPost("/api/actions/resolve-alert", ResolveAlert);
        endpoints.MapPost("/api/actions/false-positive", MarkFalsePositive);
        return endpoints;
    }

    private static async Task<IResult> StartScanAsync(
        ScanRequest request,
        IResponseService response,
        ILocalSessionService sessions,
        HttpContext context)
    {
        var type = request.Type?.Trim().ToLowerInvariant() ?? "";
        if (type is not "quick" and not "full" and not "deep")
        {
            return BadRequest("Scan type must be quick, full, or deep.");
        }

        var denied = ResponseEndpointAuthorization.Require(
            context,
            sessions,
            "defender.scan",
            type);
        if (denied is not null)
        {
            return denied;
        }

        var result = await response.StartDefenderScanAsync(
            type,
            context.RequestAborted);
        return ToResult(result);
    }

    private static async Task<IResult> BlockIpAsync(
        BlockIpRequest request,
        IResponseService response,
        ILocalSessionService sessions,
        HttpContext context)
    {
        if (!InputValidator.IsRequiredText(request.IpAddress, 64))
        {
            return BadRequest("Invalid IP address.");
        }

        var denied = ResponseEndpointAuthorization.Require(
            context,
            sessions,
            "firewall.block_ip",
            request.IpAddress);
        if (denied is not null)
        {
            return denied;
        }

        return ToResult(await response.BlockIpAsync(
            request.IpAddress,
            context.RequestAborted));
    }

    private static async Task<IResult> UnblockIpAsync(
        UnblockIpRequest request,
        IResponseService response,
        ILocalSessionService sessions,
        HttpContext context)
    {
        if (!InputValidator.IsRequiredText(request.IpAddress, 64))
        {
            return BadRequest("Invalid IP address.");
        }

        var denied = ResponseEndpointAuthorization.Require(
            context,
            sessions,
            "firewall.unblock_ip",
            request.IpAddress);
        if (denied is not null)
        {
            return denied;
        }

        return ToResult(await response.UnblockIpAsync(
            request.IpAddress,
            context.RequestAborted));
    }

    private static IResult KillProcess(
        KillProcessRequest request,
        IResponseService response,
        ILocalSessionService sessions,
        HttpContext context)
    {
        if (request.ProcessId <= 0)
        {
            return BadRequest("Invalid process ID.");
        }

        var denied = ResponseEndpointAuthorization.Require(
            context,
            sessions,
            "process.kill",
            request.ProcessId.ToString());
        if (denied is not null)
        {
            return denied;
        }

        return ToResult(response.KillProcess(request.ProcessId));
    }

    private static async Task<IResult> QuarantineFileAsync(
        QuarantineFileRequest request,
        IResponseService response,
        ILocalSessionService sessions,
        HttpContext context)
    {
        if (!InputValidator.IsAbsolutePath(request.Path))
        {
            return BadRequest("An absolute file path is required.");
        }

        var denied = ResponseEndpointAuthorization.Require(
            context,
            sessions,
            "defender.quarantine_file",
            request.Path);
        if (denied is not null)
        {
            return denied;
        }

        return ToResult(await response.QuarantineFileAsync(
            request.Path,
            context.RequestAborted));
    }

    private static async Task<IResult> DisableStartupAsync(
        DisableStartupRequest request,
        IResponseService response,
        ILocalSessionService sessions,
        HttpContext context)
    {
        if (!InputValidator.IsRequiredText(request.Name, 260) ||
            !InputValidator.IsRequiredText(request.Source, 1024) ||
            !InputValidator.IsOptionalText(request.Command, 32_000))
        {
            return BadRequest("Invalid startup item.");
        }

        var denied = ResponseEndpointAuthorization.Require(
            context,
            sessions,
            "startup.disable",
            $"{request.Source}:{request.Name}");
        if (denied is not null)
        {
            return denied;
        }

        return ToResult(await response.DisableStartupItemAsync(
            request,
            context.RequestAborted));
    }

    private static IResult ResolveAlert(
        AlertDispositionRequest request,
        IResponseService response,
        ILocalSessionService sessions,
        HttpContext context) =>
        SetAlertDisposition(
            request,
            response.ResolveAlert,
            "alert.resolved",
            sessions,
            context);

    private static IResult MarkFalsePositive(
        AlertDispositionRequest request,
        IResponseService response,
        ILocalSessionService sessions,
        HttpContext context) =>
        SetAlertDisposition(
            request,
            response.MarkFalsePositive,
            "alert.false_positive",
            sessions,
            context);

    private static IResult SetAlertDisposition(
        AlertDispositionRequest request,
        Func<string, string, ActionResultDto> action,
        string actionType,
        ILocalSessionService sessions,
        HttpContext context)
    {
        if (!InputValidator.IsIdentifier(request.AlertId) ||
            !InputValidator.IsOptionalText(request.Note, 4000))
        {
            return BadRequest("Invalid alert disposition.");
        }

        var denied = ResponseEndpointAuthorization.Require(
            context,
            sessions,
            actionType,
            request.AlertId,
            "Analyst");
        return denied ?? ToResult(action(request.AlertId, request.Note ?? ""));
    }

    private static IResult ToResult(ActionResultDto result) =>
        result.Ok ? Results.Ok(result) : Results.BadRequest(result);

    private static IResult BadRequest(string error) =>
        Results.BadRequest(new ActionResultDto(false, "", error));
}
