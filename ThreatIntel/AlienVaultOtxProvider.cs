using System.Text.Json;
using RoamSentinel.Config;
using RoamSentinel.Core;

namespace RoamSentinel.ThreatIntel;

public sealed class AlienVaultOtxProvider(
    IHttpClientFactory clients,
    ThreatIntelOptions options) : IThreatIntelProvider
{
    public string Name => "AlienVault OTX";
    public bool Enabled => options.AlienVaultOtx.Enabled;
    public bool IsConfigured =>
        Enabled && !string.IsNullOrWhiteSpace(options.AlienVaultOtx.ApiKey);
    public IReadOnlySet<string> SupportedIndicatorTypes =>
        ThreatIntelTypes.All;

    public async Task<ThreatIntelObservationDto> EnrichAsync(
        string indicator,
        string indicatorType,
        CancellationToken cancellationToken = default)
    {
        var resource = indicatorType switch
        {
            ThreatIntelTypes.Ip => indicator.Contains(':') ? "IPv6" : "IPv4",
            ThreatIntelTypes.Domain => "domain",
            ThreatIntelTypes.FileHash => "file",
            _ => throw new NotSupportedException()
        };
        var uri =
            $"{options.AlienVaultOtx.BaseUrl.TrimEnd('/')}/api/v1/indicators/" +
            $"{resource}/{Uri.EscapeDataString(indicator)}/general";
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.TryAddWithoutValidation(
            "X-OTX-API-KEY",
            options.AlienVaultOtx.ApiKey);
        using var response = await clients.CreateClient("ThreatIntel")
            .SendAsync(request, cancellationToken);
        if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return new ThreatIntelObservationDto(
                Name, false, 0, "Unknown", "Indicator was not found.", "",
                DateTimeOffset.UtcNow, null);
        }

        response.EnsureSuccessStatusCode();
        using var document = JsonDocument.Parse(
            await response.Content.ReadAsStringAsync(cancellationToken));
        var pulses = ProviderJson.Int(
            document.RootElement,
            "pulse_info",
            "count");
        return new ThreatIntelObservationDto(
            Name,
            true,
            Math.Min(100, pulses * 20),
            pulses > 0 ? "Suspicious" : "Benign",
            $"OTX pulse count={pulses}.",
            $"{options.AlienVaultOtx.BaseUrl.TrimEnd('/')}/indicator/" +
            $"{resource}/{Uri.EscapeDataString(indicator)}",
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddMinutes(options.CacheMinutes));
    }
}
