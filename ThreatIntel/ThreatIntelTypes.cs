using System.Net;

namespace RoamSentinel.ThreatIntel;

public static class ThreatIntelTypes
{
    public const string Ip = "ip";
    public const string Domain = "domain";
    public const string FileHash = "file-hash";

    public static readonly IReadOnlySet<string> All =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            Ip, Domain, FileHash
        };

    public static string Normalize(string indicator, string indicatorType)
    {
        var type = indicatorType.Trim().ToLowerInvariant();
        var value = indicator.Trim();
        if (!All.Contains(type))
        {
            throw new ArgumentException(
                "Indicator type must be ip, domain, or file-hash.");
        }

        return type switch
        {
            Ip when IPAddress.TryParse(value, out var address) =>
                address.ToString(),
            Domain when Uri.CheckHostName(value) == UriHostNameType.Dns =>
                value.TrimEnd('.').ToLowerInvariant(),
            FileHash when IsHash(value) => value.ToLowerInvariant(),
            _ => throw new ArgumentException(
                $"'{value}' is not a valid {type} indicator.")
        };
    }

    private static bool IsHash(string value) =>
        value.Length is 32 or 40 or 64 &&
        value.All(character =>
            char.IsAsciiHexDigit(character));
}
