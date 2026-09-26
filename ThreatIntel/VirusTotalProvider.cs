using System.Text.Json;
using RoamSentinel.Config;
using RoamSentinel.Core;

namespace RoamSentinel.ThreatIntel;

public sealed class VirusTotalProvider(
    IHttpClientFactory clients,
    ThreatIntelOptions options) : IThreatIntelProvider
{
    public string Name => "VirusTotal";
    public bool Enabled => options.VirusTotal.Enabled;
    public bool IsConfigured =>
        Enabled && !string.IsNullOrWhiteSpace(options.VirusTotal.ApiKey);
    public IReadOnlySet<string> SupportedIndicatorTypes =>
        ThreatIntelTypes.All;

    public async Task<ThreatIntelObservationDto> EnrichAsync(
        string indicator,
        string indicatorType,
        CancellationToken cancellationToken = default)
    {
        var resource = indicatorType switch
        {
            ThreatIntelTypes.Ip => "ip_addresses",
            ThreatIntelTypes.Domain => "domains",
            ThreatIntelTypes.FileHash => "files",
            _ => throw new NotSupportedException()
        };
        var uri =
            $"{options.VirusTotal.BaseUrl.TrimEnd('/')}/api/v3/{resource}/" +
            Uri.EscapeDataString(indicator);
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.TryAddWithoutValidation(
            "x-apikey",
            options.VirusTotal.ApiKey);
        using var response = await clients.CreateClient("ThreatIntel")
            .SendAsync(request, cancellationToken);
        if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return Empty(indicator, indicatorType);
        }

        response.EnsureSuccessStatusCode();
        using var document = JsonDocument.Parse(
            await response.Content.ReadAsStringAsync(cancellationToken));
        var root = document.RootElement;
        var malicious = ProviderJson.Int(
            root, "data", "attributes", "last_analysis_stats", "malicious");
        var suspicious = ProviderJson.Int(
            root, "data", "attributes", "last_analysis_stats", "suspicious");
        var harmless = ProviderJson.Int(
            root, "data", "attributes", "last_analysis_stats", "harmless");
        var undetected = ProviderJson.Int(
            root, "data", "attributes", "last_analysis_stats", "undetected");
        var total = malicious + suspicious + harmless + undetected;
        var reputation = malicious >= options.VirusTotalMaliciousThreshold
            ? "Malicious"
            : malicious > 0 || suspicious > 0
                ? "Suspicious"
                : "Benign";
        var confidence = total == 0
            ? 0
            : Math.Clamp(
                (int)Math.Round(
                    (malicious + suspicious * 0.5) / total * 100),
                0,
                100);
        return new ThreatIntelObservationDto(
            Name,
            true,
            confidence,
            reputation,
            $"Analysis engines: malicious={malicious}, suspicious={suspicious}, harmless={harmless}, undetected={undetected}.",
            Reference(indicator, indicatorType),
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddMinutes(options.CacheMinutes));
    }

    private ThreatIntelObservationDto Empty(
        string indicator,
        string indicatorType) =>
        new(
            Name,
            false,
            0,
            "Unknown",
            "Indicator was not found.",
            Reference(indicator, indicatorType),
            DateTimeOffset.UtcNow,
            null);

    private static string Reference(string indicator, string indicatorType)
    {
        var path = indicatorType switch
        {
            ThreatIntelTypes.Ip => "ip-address",
            ThreatIntelTypes.Domain => "domain",
            _ => "file"
        };
        return $"https://www.virustotal.com/gui/{path}/" +
            Uri.EscapeDataString(indicator);
    }
}
