using System.Text.Json;
using RoamSentinel.Config;
using RoamSentinel.Core;

namespace RoamSentinel.ThreatIntel;

public sealed class AbuseIpDbProvider(
    IHttpClientFactory clients,
    ThreatIntelOptions options) : IThreatIntelProvider
{
    private static readonly IReadOnlySet<string> Supported =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ThreatIntelTypes.Ip
        };

    public string Name => "AbuseIPDB";
    public bool Enabled => options.AbuseIpDb.Enabled;
    public bool IsConfigured =>
        Enabled && !string.IsNullOrWhiteSpace(options.AbuseIpDb.ApiKey);
    public IReadOnlySet<string> SupportedIndicatorTypes => Supported;

    public async Task<ThreatIntelObservationDto> EnrichAsync(
        string indicator,
        string indicatorType,
        CancellationToken cancellationToken = default)
    {
        var uri =
            $"{options.AbuseIpDb.BaseUrl.TrimEnd('/')}/api/v2/check" +
            $"?ipAddress={Uri.EscapeDataString(indicator)}" +
            $"&maxAgeInDays={options.AbuseIpDbMaxAgeDays}";
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.TryAddWithoutValidation(
            "Key",
            options.AbuseIpDb.ApiKey);
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        using var response = await clients.CreateClient("ThreatIntel")
            .SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
        using var document = JsonDocument.Parse(
            await response.Content.ReadAsStringAsync(cancellationToken));
        var root = document.RootElement;
        var score = ProviderJson.Int(root, "data", "abuseConfidenceScore");
        var reports = ProviderJson.Int(root, "data", "totalReports");
        var reputation = score >= 75
            ? "Malicious"
            : score >= 25 || reports > 0
                ? "Suspicious"
                : "Benign";
        return new ThreatIntelObservationDto(
            Name,
            true,
            Math.Clamp(score, 0, 100),
            reputation,
            $"Abuse confidence={score}; reports={reports}; lookback={options.AbuseIpDbMaxAgeDays} days.",
            $"https://www.abuseipdb.com/check/{Uri.EscapeDataString(indicator)}",
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddMinutes(options.CacheMinutes));
    }
}
