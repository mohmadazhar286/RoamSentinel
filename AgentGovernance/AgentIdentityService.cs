using RoamSentinel.Config;
using RoamSentinel.Core;

namespace RoamSentinel.AgentGovernance;

public sealed class AgentIdentityService(
    IAgentRegistryRepository repository,
    AgentGovernanceOptions options) : IAgentIdentityService
{
    public AgentIdentityDto Identify(
        string name,
        string path,
        string commandLine = "")
    {
        var identity = $"{name} {path} {commandLine}";
        var match = repository.GetDefinitions()
            .SelectMany(definition => definition.IdentityMarkers.Select(
                marker => new { Definition = definition, Marker = marker }))
            .Where(item =>
                !string.IsNullOrWhiteSpace(item.Marker) &&
                identity.Contains(
                    item.Marker,
                    StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(item => item.Marker.Length)
            .Select(item => item.Definition)
            .FirstOrDefault();

        if (match is not null)
        {
            var trustedPath = match.TrustedPathMarkers.Any(marker =>
                path.Contains(marker, StringComparison.OrdinalIgnoreCase));
            return new AgentIdentityDto(
                true,
                match.AgentKey,
                match.Name,
                match.Vendor,
                trustedPath,
                match.SharedHost || IsSharedHost(path));
        }

        var fallback = options.IdentityMarkers
            .OrderByDescending(marker => marker.Length)
            .FirstOrDefault(marker => identity.Contains(
                marker,
                StringComparison.OrdinalIgnoreCase));
        return fallback is null
            ? new AgentIdentityDto(false, "", "", "", false, false)
            : new AgentIdentityDto(
                true,
                $"unknown:{fallback.ToLowerInvariant()}",
                string.IsNullOrWhiteSpace(name) ? fallback : name,
                "Unknown",
                false,
                IsSharedHost(path));
    }

    private static bool IsSharedHost(string path)
    {
        var fileName = Path.GetFileNameWithoutExtension(path);
        return fileName.Equals("node", StringComparison.OrdinalIgnoreCase) ||
               fileName.Equals("python", StringComparison.OrdinalIgnoreCase) ||
               fileName.Equals("pythonw", StringComparison.OrdinalIgnoreCase) ||
               fileName.Equals("code", StringComparison.OrdinalIgnoreCase);
    }
}
