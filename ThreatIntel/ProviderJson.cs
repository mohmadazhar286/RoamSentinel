using System.Text.Json;

namespace RoamSentinel.ThreatIntel;

internal static class ProviderJson
{
    public static int Int(JsonElement element, params string[] path)
    {
        var value = Navigate(element, path);
        return value is { ValueKind: JsonValueKind.Number } &&
            value.Value.TryGetInt32(out var number)
                ? number
                : 0;
    }

    public static string String(JsonElement element, params string[] path)
    {
        var value = Navigate(element, path);
        return value is { ValueKind: JsonValueKind.String }
            ? value.Value.GetString() ?? ""
            : "";
    }

    public static JsonElement? Navigate(
        JsonElement element,
        params string[] path)
    {
        var current = element;
        foreach (var property in path)
        {
            if (current.ValueKind != JsonValueKind.Object ||
                !current.TryGetProperty(property, out current))
            {
                return null;
            }
        }

        return current;
    }
}
