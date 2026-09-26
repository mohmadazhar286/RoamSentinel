using System.Security.Cryptography;
using System.Text.Json;
using RoamSentinel.Core;

namespace RoamSentinel.CodeGate;

public sealed class CodeGateBundleService(
    ICodeGateBundleRepository repository) : ICodeGateBundleService
{
    private static readonly HashSet<string> AllowedTypes = new(
        ["codegate-rules", "dependency-advisory-cache", "ioc-bundle"],
        StringComparer.OrdinalIgnoreCase);

    public CodeGateBundleDto ImportBundle(
        CodeGateBundleImportRequest request,
        string actor)
    {
        if (string.IsNullOrWhiteSpace(request.Path))
        {
            throw new ArgumentException("Offline bundle path is required.");
        }

        var path = Path.GetFullPath(request.Path);
        if (!File.Exists(path))
        {
            throw new FileNotFoundException("Offline bundle was not found.", path);
        }

        var content = File.ReadAllText(path);
        var actualSha = Sha256(File.ReadAllBytes(path));
        if (!string.IsNullOrWhiteSpace(request.ExpectedSha256) &&
            !actualSha.Equals(
                request.ExpectedSha256,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Offline bundle SHA-256 does not match the expected value.");
        }

        using var document = JsonDocument.Parse(content);
        var root = document.RootElement;
        var component = Text(root, "component");
        var bundleType = Text(root, "bundleType");
        var schemaVersion = Text(root, "schemaVersion");
        var name = Text(root, "name");
        var version = Text(root, "version");
        var source = Text(root, "source");
        var signature = Text(root, "signature");
        var generatedAt = Date(root, "generatedAt");

        if (!component.Equals("RS CodeGate", StringComparison.OrdinalIgnoreCase) &&
            !component.Equals("RoamSentinel", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Offline bundle component is not accepted.");
        }

        if (!AllowedTypes.Contains(bundleType))
        {
            throw new InvalidDataException(
                "Offline bundle type is not supported.");
        }

        if (string.IsNullOrWhiteSpace(schemaVersion) ||
            string.IsNullOrWhiteSpace(name) ||
            string.IsNullOrWhiteSpace(version) ||
            generatedAt == DateTimeOffset.MinValue)
        {
            throw new InvalidDataException(
                "Offline bundle manifest is incomplete.");
        }

        var bundle = new CodeGateBundleDto(
            Guid.NewGuid().ToString("N"),
            DateTimeOffset.UtcNow,
            component,
            bundleType,
            name,
            version,
            schemaVersion,
            generatedAt,
            string.IsNullOrWhiteSpace(source) ? "offline-import" : source,
            actualSha,
            signature,
            true,
            "imported",
            "Offline bundle manifest validated and recorded. Activation is handled by a later policy pass.",
            string.IsNullOrWhiteSpace(actor) ? "local-user" : actor);
        repository.Save(bundle);
        return bundle;
    }

    public IReadOnlyList<CodeGateBundleDto> GetRecentBundles(int limit) =>
        repository.GetRecent(limit);

    private static string Sha256(byte[] content) =>
        Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();

    private static string Text(JsonElement root, string property) =>
        root.TryGetProperty(property, out var value)
            ? value.ToString()
            : "";

    private static DateTimeOffset Date(JsonElement root, string property) =>
        root.TryGetProperty(property, out var value) &&
        DateTimeOffset.TryParse(value.ToString(), out var date)
            ? date
            : DateTimeOffset.MinValue;
}
