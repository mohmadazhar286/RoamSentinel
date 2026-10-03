using RoamSentinel.Core;
using RoamSentinel.App.Security;

namespace RoamSentinel.App.Api;

public static class AgentGovernanceEndpoints
{
    public static IEndpointRouteBuilder MapAgentGovernanceEndpoints(
        this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/api/actions/authorize-agent", AuthorizeAgentAsync);
        endpoints.MapPost("/api/actions/block-agent", BlockAgentAsync);
        endpoints.MapPost("/api/actions/unblock-agent", UnblockAgentAsync);
        endpoints.MapPost("/api/actions/block-agent-egress", BlockAgentAsync);
        endpoints.MapPost("/api/actions/unblock-agent-egress", UnblockAgentAsync);
        endpoints.MapGet("/api/v1/agents/egress-rules", GetAgentEgressRules);
        endpoints.MapPost("/api/v1/agents/mcp-events", RecordMcpEventAsync);
        endpoints.MapGet("/api/v1/agents/mcp-events", GetRecentMcpEvents);
        endpoints.MapGet("/api/v1/agents/mcp-summary", GetMcpSummary);
        endpoints.MapPost(
            "/api/actions/enforce-agent-policy",
            EnforceAgentPolicyAsync);
        return endpoints;
    }

    private static async Task<IResult> AuthorizeAgentAsync(
        AgentPolicyRequest request,
        IAgentGovernanceService governance,
        IResponseService response,
        ILocalSessionService sessions,
        HttpContext context)
    {
        if (!InputValidator.IsAbsolutePath(request.Path))
        {
            return Results.BadRequest(new ActionResultDto(
                false,
                "",
                "Agent path is required."));
        }

        var denied = ResponseEndpointAuthorization.Require(
            context,
            sessions,
            "agent.authorize",
            request.Path);
        if (denied is not null)
        {
            return denied;
        }

        governance.Authorize(request.Path);
        var result = await response.UnblockAgentAsync(
            request.Path,
            context.RequestAborted);
        return result.Ok
            ? Results.Ok(new ActionResultDto(
                true,
                $"Authorized {request.Path}",
                ""))
            : Results.Ok(result);
    }

    private static async Task<IResult> BlockAgentAsync(
        AgentPolicyRequest request,
        IAgentGovernanceService governance,
        IResponseService response,
        ILocalSessionService sessions,
        HttpContext context)
    {
        if (!InputValidator.IsAbsolutePath(request.Path))
        {
            return Results.BadRequest(new ActionResultDto(
                false,
                "",
                "Agent path is required."));
        }

        var denied = ResponseEndpointAuthorization.Require(
            context,
            sessions,
            "firewall.block_agent",
            request.Path);
        if (denied is not null)
        {
            return denied;
        }

        governance.Block(request.Path);
        var result = await response.BlockAgentAsync(
            request.Path,
            context.RequestAborted);
        return Results.Ok(result);
    }

    private static async Task<IResult> UnblockAgentAsync(
        AgentPolicyRequest request,
        IAgentGovernanceService governance,
        IResponseService response,
        ILocalSessionService sessions,
        HttpContext context)
    {
        if (!InputValidator.IsAbsolutePath(request.Path))
        {
            return Results.BadRequest(new ActionResultDto(
                false,
                "",
                "Agent path is required."));
        }

        var denied = ResponseEndpointAuthorization.Require(
            context,
            sessions,
            "firewall.unblock_agent",
            request.Path);
        if (denied is not null)
        {
            return denied;
        }

        governance.Unblock(request.Path);
        var result = await response.UnblockAgentAsync(
            request.Path,
            context.RequestAborted);
        return Results.Ok(result);
    }

    private static async Task<IResult> EnforceAgentPolicyAsync(
        ISecuritySnapshotService snapshots,
        IAgentGovernanceService governance,
        IResponseService response,
        IEventLogService eventLog,
        ILocalSessionService sessions,
        HttpContext context)
    {
        var denied = ResponseEndpointAuthorization.Require(
            context,
            sessions,
            "agent.enforce_policy",
            "all-unapproved-agents");
        if (denied is not null)
        {
            return denied;
        }

        var snapshot = await snapshots.CollectAsync(context.RequestAborted);
        var governed = snapshot.Raw.GovernedAgents ??
            governance.Observe(snapshot.Raw);
        var paths = governed
            .Where(agent =>
                agent.IsRunning &&
                !agent.NetworkAuthorized &&
                agent.CanEnforcePath &&
                !string.IsNullOrWhiteSpace(agent.ExecutablePath))
            .Select(agent => agent.ExecutablePath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        var skippedSharedHosts = governed.Count(agent =>
            agent.IsRunning &&
            !agent.NetworkAuthorized &&
            !agent.CanEnforcePath);

        var blocked = new List<string>();
        var errors = new List<string>();
        foreach (var path in paths)
        {
            governance.Block(path);
            var result = await response.BlockAgentAsync(
                path,
                context.RequestAborted);
            if (result.Ok)
            {
                blocked.Add(path);
            }
            else
            {
                errors.Add($"{path}: {result.Error}");
            }
        }

        eventLog.RecordAction(
            "Agent policy enforced",
            blocked.Count > 0 ? "High" : "Low",
            $"{blocked.Count} unapproved agent executable(s) blocked; " +
            $"{skippedSharedHosts} shared host process(es) left for review.");
        return Results.Ok(new ActionResultDto(
            errors.Count == 0,
            string.Join(Environment.NewLine, blocked) +
            (skippedSharedHosts > 0
                ? $"{Environment.NewLine}{skippedSharedHosts} shared host process(es) require manual review."
                : ""),
            string.Join(Environment.NewLine, errors)));
    }

    private static IResult GetAgentEgressRules(
        IAgentEgressRuleRepository egressRules,
        ILocalSessionService sessions,
        HttpContext context)
    {
        return Results.Ok(egressRules.GetAll());
    }

    private static IResult RecordMcpEventAsync(
        McpToolCallRequest request,
        IMcpGovernanceService mcpService,
        ILocalSessionService sessions,
        HttpContext context)
    {
        var denied = EndpointSecurity.RequireRole(
            context,
            sessions,
            "Analyst");
        if (denied is not null)
        {
            return denied;
        }

        if (string.IsNullOrWhiteSpace(request.AgentKey) ||
            string.IsNullOrWhiteSpace(request.ToolName) ||
            request.AgentKey.Length > 128 ||
            request.ToolName.Length > 128 ||
            (request.ServerName?.Length ?? 0) > 128 ||
            (request.ArgumentsJson?.Length ?? 0) > 100_000)
        {
            return Results.BadRequest(new { error = "Invalid MCP tool call payload." });
        }

        var session = sessions.Resolve(context.Request);
        var result = mcpService.AssessAndRecord(request, session?.Role ?? "local-user");
        return Results.Ok(result);
    }

    private static IResult GetRecentMcpEvents(
        IMcpGovernanceService mcpService,
        int? limit)
    {
        return Results.Ok(mcpService.GetRecentEvents(Math.Clamp(limit ?? 100, 1, 500)));
    }

    private static IResult GetMcpSummary(
        IMcpGovernanceService mcpService,
        int? limit)
    {
        return Results.Ok(mcpService.GetSummary(Math.Clamp(limit ?? 50, 1, 500)));
    }
}
