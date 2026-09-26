using System.Text;
using System.Text.Json;
using RoamSentinel.Config;
using RoamSentinel.Core;

namespace RoamSentinel.ThreatIntel;

public sealed class MispProvider(
    IHttpClientFactory clients,
    ThreatIntelOptions options) : IThreatIntelProvider
{
    public string Name => "MISP";
    public bool Enabled => options.Misp.Enabled;
    public bool IsConfigured =>
        Enabled &&
        !string.IsNullOrWhiteSpace(options.Misp.ApiKey) &&
        Uri.IsWellFormedUriString(options.Misp.BaseUrl, UriKind.Absolute);
    public IReadOnlySet<string> SupportedIndicatorTypes =>
        ThreatIntelTypes.All;

    public async Task<ThreatIntelObservationDto> EnrichAsync(
        string indicator,
        string indicatorType,
        CancellationToken cancellationToken = default)
    {
        var uri =
            $"{options.Misp.BaseUrl.TrimEnd('/')}/attributes/restSearch";
        using var request = new HttpRequestMessage(HttpMethod.Post, uri);
        request.Headers.TryAddWithoutValidation(
            "Authorization",
            options.Misp.ApiKey);
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Content = new StringContent(
            JsonSerializer.Serialize(new
            {
                returnFormat = "json",
                value = indicator,
                limit = 25
            }),
            Encoding.UTF8,
            "application/json");
        using var response = await clients.CreateClient("Misp")
            .SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
        using var document = JsonDocument.Parse(
            await response.Content.ReadAsStringAsync(cancellationToken));
        var attributes = FindAttributes(document.RootElement);
        var toIds = attributes.Count(attribute =>
            attribute.TryGetProperty("to_ids", out var value) &&
            (value.ValueKind is JsonValueKind.True ||
             value.ValueKind == JsonValueKind.Number &&
             value.GetInt32() != 0));
        var reputation = toIds > 0
            ? "Malicious"
            : attributes.Count > 0
                ? "Suspicious"
                : "Benign";
        return new ThreatIntelObservationDto(
            Name,
            true,
            attributes.Count == 0
                ? 0
                : toIds > 0 ? 90 : 60,
            reputation,
            $"Matching attributes={attributes.Count}; IDS-marked={toIds}.",
            options.Misp.BaseUrl,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddMinutes(options.CacheMinutes));
    }

    private static IReadOnlyList<JsonElement> FindAttributes(JsonElement root)
    {
        if (root.ValueKind == JsonValueKind.Object &&
            root.TryGetProperty("Attribute", out var direct) &&
            direct.ValueKind == JsonValueKind.Array)
        {
            return direct.EnumerateArray().ToList();
        }

        if (root.ValueKind == JsonValueKind.Object &&
            root.TryGetProperty("response", out var response))
        {
            if (response.ValueKind == JsonValueKind.Object &&
                response.TryGetProperty("Attribute", out var nested) &&
                nested.ValueKind == JsonValueKind.Array)
            {
                return nested.EnumerateArray().ToList();
            }

            if (response.ValueKind == JsonValueKind.Array)
            {
                return response.EnumerateArray().ToList();
            }
        }

        return [];
    }
}
