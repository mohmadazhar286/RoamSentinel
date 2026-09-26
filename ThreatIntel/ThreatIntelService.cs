using System.Text.Json;
using RoamSentinel.Config;
using RoamSentinel.Core;

namespace RoamSentinel.ThreatIntel;

public sealed class ThreatIntelService(
    IEnumerable<IThreatIntelProvider> providers,
    IThreatIndicatorRepository indicators,
    ThreatIntelOptions options) : IThreatIntelService
{
    private readonly IReadOnlyList<IThreatIntelProvider> _providers =
        providers.ToList();

    public Task<ThreatIntelResult> EnrichIpAsync(
        string indicator,
        CancellationToken cancellationToken = default) =>
        EnrichAsync(indicator, ThreatIntelTypes.Ip, cancellationToken);

    public Task<ThreatIntelResult> EnrichDomainAsync(
        string indicator,
        CancellationToken cancellationToken = default) =>
        EnrichAsync(indicator, ThreatIntelTypes.Domain, cancellationToken);

    public Task<ThreatIntelResult> EnrichFileHashAsync(
        string indicator,
        CancellationToken cancellationToken = default) =>
        EnrichAsync(indicator, ThreatIntelTypes.FileHash, cancellationToken);

    public async Task<ThreatIntelResult> EnrichAsync(
        string indicator,
        string indicatorType,
        CancellationToken cancellationToken = default)
    {
        var type = indicatorType.Trim().ToLowerInvariant();
        var normalized = ThreatIntelTypes.Normalize(indicator, type);
        var now = DateTimeOffset.UtcNow;
        var observations = new List<ThreatIntelObservationDto>();
        var local = indicators.FindActive(
            normalized,
            type,
            "Local",
            now);
        if (local is not null)
        {
            observations.Add(ToObservation(local, fromCache: true));
        }

        foreach (var provider in _providers.Where(provider =>
            provider.Enabled &&
            provider.IsConfigured &&
            provider.SupportedIndicatorTypes.Contains(type)))
        {
            var cached = indicators.FindActive(
                normalized,
                type,
                provider.Name,
                now);
            if (cached is not null)
            {
                observations.Add(ToObservation(cached, fromCache: true));
                continue;
            }

            ThreatIntelObservationDto observation;
            try
            {
                observation = await provider.EnrichAsync(
                    normalized,
                    type,
                    cancellationToken);
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                observation = new ThreatIntelObservationDto(
                    provider.Name,
                    false,
                    0,
                    "Unknown",
                    "Provider query failed.",
                    "",
                    now,
                    null);
            }

            observations.Add(observation);
            if (observation.HasIntelligence)
            {
                indicators.Upsert(
                    new ThreatIndicatorDto(
                        normalized,
                        type,
                        observation.Reputation,
                        observation.Confidence,
                        provider.Name,
                        observation.ObservedAt,
                        observation.ObservedAt,
                        observation.ExpiresAt ??
                            now.AddMinutes(options.CacheMinutes),
                        observation.Summary,
                        [],
                        JsonSerializer.Serialize(new
                        {
                            observation.ReferenceUrl
                        })),
                    "system");
            }
        }

        var intelligence = observations
            .Where(observation => observation.HasIntelligence)
            .ToList();
        var strongest = intelligence
            .OrderByDescending(observation =>
                ReputationRank(observation.Reputation))
            .ThenByDescending(observation => observation.Confidence)
            .FirstOrDefault();
        return new ThreatIntelResult(
            normalized,
            type,
            intelligence.Count > 0,
            strongest?.Confidence ?? 0,
            strongest?.Reputation ?? "Unknown",
            intelligence.Count > 0 &&
                intelligence.All(observation => observation.FromCache),
            observations,
            intelligence
                .Where(observation => observation.ExpiresAt is not null)
                .Select(observation => observation.ExpiresAt)
                .DefaultIfEmpty(null)
                .Min());
    }

    public IReadOnlyList<ThreatIntelProviderStatusDto> GetProviderStatus() =>
        _providers.Select(provider => new ThreatIntelProviderStatusDto(
                provider.Name,
                provider.Enabled,
                provider.IsConfigured,
                provider.SupportedIndicatorTypes
                    .OrderBy(value => value)
                    .ToList()))
            .ToList();

    private static ThreatIntelObservationDto ToObservation(
        ThreatIndicatorDto indicator,
        bool fromCache) =>
        new(
            indicator.Source,
            true,
            indicator.Confidence,
            indicator.Reputation,
            indicator.Description,
            ReadReferenceUrl(indicator.MetadataJson),
            indicator.LastSeenAt,
            indicator.ExpiresAt,
            fromCache);

    private static string ReadReferenceUrl(string metadataJson)
    {
        try
        {
            using var document = JsonDocument.Parse(metadataJson);
            return document.RootElement.TryGetProperty(
                "ReferenceUrl",
                out var value)
                ? value.GetString() ?? ""
                : "";
        }
        catch
        {
            return "";
        }
    }

    private static int ReputationRank(string reputation) =>
        reputation.ToLowerInvariant() switch
        {
            "blocked" => 5,
            "malicious" => 4,
            "high-risk" => 3,
            "suspicious" => 2,
            "benign" or "clean" or "harmless" => 1,
            _ => 0
        };
}
