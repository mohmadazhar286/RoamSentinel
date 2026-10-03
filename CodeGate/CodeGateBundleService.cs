using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using RoamSentinel.Core;

namespace RoamSentinel.CodeGate;

public sealed class CodeGateBundleService(
    ICodeGateBundleRepository repository,
    ICodeGateActiveRuleRepository? activeRules = null) : ICodeGateBundleService
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

        var bundleId = Guid.NewGuid().ToString("N");
        var status = "imported";
        var message = "Offline bundle manifest validated and recorded. Activation is handled by a later policy pass.";

        if (bundleType.Equals("codegate-rules", StringComparison.OrdinalIgnoreCase))
        {
            var parsedRules = ParseRules(root, bundleId);
            if (parsedRules.Count > 0 && activeRules is not null)
            {
                activeRules.SaveRules(bundleId, parsedRules);
                status = "active";
                message = $"Offline bundle manifest validated and {parsedRules.Count} rules activated.";
            }
        }

        var bundle = new CodeGateBundleDto(
            bundleId,
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
            status,
            message,
            string.IsNullOrWhiteSpace(actor) ? "local-user" : actor);
        repository.Save(bundle);
        return bundle;
    }

    public IReadOnlyList<CodeGateBundleDto> GetRecentBundles(int limit) =>
        repository.GetRecent(limit);

    private static List<CodeGateActiveRuleDto> ParseRules(JsonElement root, string bundleId)
    {
        var rules = new List<CodeGateActiveRuleDto>();
        if (!root.TryGetProperty("rules", out var rulesElement) ||
            rulesElement.ValueKind != JsonValueKind.Array)
        {
            return rules;
        }

        foreach (var ruleElem in rulesElement.EnumerateArray())
        {
            var ruleId = Text(ruleElem, "ruleId");
            if (string.IsNullOrWhiteSpace(ruleId))
            {
                ruleId = Text(ruleElem, "id");
            }
            if (string.IsNullOrWhiteSpace(ruleId))
            {
                ruleId = $"CG-DYN-{Guid.NewGuid():N}"[..12].ToUpperInvariant();
            }

            var name = Text(ruleElem, "name");
            if (string.IsNullOrWhiteSpace(name))
            {
                name = ruleId;
            }

            var severity = Text(ruleElem, "severity");
            if (string.IsNullOrWhiteSpace(severity))
            {
                severity = "Medium";
            }

            var riskScore = 40;
            if (ruleElem.TryGetProperty("riskScore", out var riskScoreElem) &&
                riskScoreElem.TryGetInt32(out var parsedRisk))
            {
                riskScore = parsedRisk;
            }
            else if (ruleElem.TryGetProperty("risk_score", out var riskScoreElem2) &&
                     riskScoreElem2.TryGetInt32(out var parsedRisk2))
            {
                riskScore = parsedRisk2;
            }
            else
            {
                riskScore = severity.ToLowerInvariant() switch
                {
                    "critical" => 90,
                    "high" => 75,
                    "medium" => 45,
                    "low" => 25,
                    _ => 15
                };
            }

            var pattern = Text(ruleElem, "pattern");
            if (string.IsNullOrWhiteSpace(pattern))
            {
                throw new InvalidDataException($"Rule '{ruleId}' is missing a regex pattern.");
            }

            try
            {
                _ = new Regex(
                    pattern,
                    RegexOptions.Compiled,
                    TimeSpan.FromSeconds(2));
            }
            catch (ArgumentException ex)
            {
                throw new InvalidDataException(
                    $"Rule '{ruleId}' contains invalid regex pattern '{pattern}': {ex.Message}",
                    ex);
            }

            var explanation = Text(ruleElem, "explanation");
            if (string.IsNullOrWhiteSpace(explanation))
            {
                explanation = Text(ruleElem, "description");
            }
            if (string.IsNullOrWhiteSpace(explanation))
            {
                explanation = $"Rule {name} matched.";
            }

            var enabled = true;
            if (ruleElem.TryGetProperty("enabled", out var enabledElem) &&
                (enabledElem.ValueKind == JsonValueKind.True || enabledElem.ValueKind == JsonValueKind.False))
            {
                enabled = enabledElem.GetBoolean();
            }

            rules.Add(new CodeGateActiveRuleDto(
                ruleId,
                bundleId,
                name,
                severity,
                riskScore,
                pattern,
                explanation,
                enabled));
        }

        return rules;
    }

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
