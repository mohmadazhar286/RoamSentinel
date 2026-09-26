using RoamSentinel.Core;
using RoamSentinel.ThreatIntel;
using RoamSentinel.App.Security;

namespace RoamSentinel.App.Api;

public static class ThreatIntelEndpoints
{
    private static readonly HashSet<string> AllowedReputations =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "Benign",
            "Suspicious",
            "Malicious",
            "High-Risk",
            "Blocked"
        };

    public static IEndpointRouteBuilder MapThreatIntelEndpoints(
        this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost(
            "/api/threat-intel/enrich",
            EnrichAsync);
        endpoints.MapPost(
            "/api/threat-intel/local-iocs",
            UpsertLocal);
        endpoints.MapPost(
            "/api/threat-intel/local-iocs/remove",
            RemoveLocal);
        return endpoints;
    }

    private static async Task<IResult> EnrichAsync(
        ThreatIntelQueryRequest request,
        IThreatIntelService threatIntel,
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

        if (!InputValidator.IsRequiredText(request.Indicator, 2048) ||
            !InputValidator.IsRequiredText(request.IndicatorType, 32))
        {
            return Results.BadRequest(new { error = "Invalid indicator." });
        }

        try
        {
            return Results.Ok(await threatIntel.EnrichAsync(
                request.Indicator,
                request.IndicatorType,
                context.RequestAborted));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }

    private static IResult UpsertLocal(
        LocalIocRequest request,
        IThreatIndicatorRepository indicators,
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

        if (!InputValidator.IsRequiredText(request.Indicator, 2048) ||
            !InputValidator.IsRequiredText(request.IndicatorType, 32) ||
            !InputValidator.IsOptionalText(request.Description, 4000) ||
            (request.Tags?.Any(tag =>
                !InputValidator.IsRequiredText(tag, 128)) ?? false))
        {
            return Results.BadRequest(new { error = "Invalid IOC input." });
        }

        if (!AllowedReputations.Contains(request.Reputation))
        {
            return Results.BadRequest(new
            {
                error =
                    "Reputation must be Benign, Suspicious, Malicious, High-Risk, or Blocked."
            });
        }

        if (request.Confidence is < 0 or > 100)
        {
            return Results.BadRequest(new
            {
                error = "Confidence must be between 0 and 100."
            });
        }

        try
        {
            var type = request.IndicatorType.Trim().ToLowerInvariant();
            var indicator = ThreatIntelTypes.Normalize(
                request.Indicator,
                type);
            var now = DateTimeOffset.UtcNow;
            var result = indicators.Upsert(
                new ThreatIndicatorDto(
                    indicator,
                    type,
                    NormalizeReputation(request.Reputation),
                    request.Confidence,
                    "Local",
                    now,
                    now,
                    request.ExpiresAt,
                    request.Description.Trim(),
                    (request.Tags ?? [])
                        .Where(tag => !string.IsNullOrWhiteSpace(tag))
                        .Select(tag => tag.Trim())
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToList(),
                    "{}"),
                "local-user");
            return Results.Ok(result);
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }

    private static IResult RemoveLocal(
        ThreatIntelQueryRequest request,
        IThreatIndicatorRepository indicators,
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

        if (!InputValidator.IsRequiredText(request.Indicator, 2048) ||
            !InputValidator.IsRequiredText(request.IndicatorType, 32))
        {
            return Results.BadRequest(new { error = "Invalid indicator." });
        }

        try
        {
            var type = request.IndicatorType.Trim().ToLowerInvariant();
            var indicator = ThreatIntelTypes.Normalize(
                request.Indicator,
                type);
            return indicators.RemoveLocal(indicator, type)
                ? Results.Ok(new { removed = true })
                : Results.NotFound(new
                {
                    error = "Local IOC was not found."
                });
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }

    private static string NormalizeReputation(string value) =>
        value.ToLowerInvariant() switch
        {
            "high-risk" => "High-Risk",
            _ => char.ToUpperInvariant(value[0]) +
                value[1..].ToLowerInvariant()
        };
}
