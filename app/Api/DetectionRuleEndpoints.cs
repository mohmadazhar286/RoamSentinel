using RoamSentinel.Core;
using RoamSentinel.App.Security;

namespace RoamSentinel.App.Api;

public static class DetectionRuleEndpoints
{
    public static IEndpointRouteBuilder MapDetectionRuleEndpoints(
        this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost(
            "/api/detection/rules/{ruleId}/enabled",
            SetEnabled);
        return endpoints;
    }

    private static IResult SetEnabled(
        string ruleId,
        RuleEnabledRequest request,
        IDetectionRuleRepository rules,
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

        if (!InputValidator.IsIdentifier(ruleId))
        {
            return Results.BadRequest(new
            {
                error = "Rule ID is required."
            });
        }

        var updated = rules.SetEnabled(ruleId, request.Enabled);
        return updated is null
            ? Results.NotFound(new
            {
                error = $"Detection rule '{ruleId}' was not found."
            })
            : Results.Ok(updated);
    }
}
