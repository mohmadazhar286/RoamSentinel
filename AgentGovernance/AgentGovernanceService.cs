using System.Net;
using RoamSentinel.Config;
using RoamSentinel.Core;

namespace RoamSentinel.AgentGovernance;

public sealed class AgentGovernanceService(
    IAgentPolicyRepository policies,
    IAgentRegistryRepository registry,
    IAgentIdentityService identities,
    AgentGovernanceOptions options,
    IAuditRepository audit,
    IStructuredLogService logs) : IAgentGovernanceService
{
    private readonly object _persistenceGate = new();
    private DateTimeOffset _lastPersistedAt = DateTimeOffset.MinValue;

    public AgentPolicy GetPolicy() => policies.Load();

    public AgentEvaluation Evaluate(
        ProcessTelemetry process,
        IReadOnlyCollection<ConnectionTelemetry>? connections = null)
    {
        var identity = identities.Identify(
            process.Name,
            process.Path,
            process.CommandLine);
        if (!identity.IsAgent)
        {
            return new AgentEvaluation(false, true, false);
        }

        var observation = BuildObservation(
            identity,
            process.Path,
            true,
            process.ProcessId,
            connections?.Where(item => item.ProcessId == process.ProcessId)
                .ToList() ?? [],
            DateTimeOffset.UtcNow);
        return new AgentEvaluation(
            true,
            observation.NetworkAuthorized,
            observation.Status == "blocked",
            observation.Name,
            observation.Vendor,
            observation.Status,
            observation.RiskScore,
            observation.RiskReason);
    }

    public IReadOnlyList<AgentGovernanceDto> Observe(
        TelemetrySnapshot snapshot)
    {
        var running = snapshot.Processes
            .Select(process => new
            {
                Process = process,
                Identity = identities.Identify(
                    process.Name,
                    process.Path,
                    process.CommandLine)
            })
            .Where(item =>
                item.Identity.IsAgent &&
                !string.IsNullOrWhiteSpace(item.Process.Path))
            .Select(item => BuildObservation(
                item.Identity,
                item.Process.Path,
                true,
                item.Process.ProcessId,
                snapshot.Connections
                    .Where(connection =>
                        connection.ProcessId == item.Process.ProcessId)
                    .ToList(),
                snapshot.ObservedAt));

        var installed = snapshot.InstalledAgents
            .Where(item =>
                !item.IsRunning &&
                !string.IsNullOrWhiteSpace(item.Path))
            .Select(item => new
            {
                Item = item,
                Identity = identities.Identify(item.Name, item.Path)
            })
            .Where(item => item.Identity.IsAgent)
            .Select(item => BuildObservation(
                item.Identity,
                item.Item.Path,
                false,
                null,
                [],
                snapshot.ObservedAt));

        var observations = running
            .Concat(installed)
            .GroupBy(
                item => item.ExecutablePath,
                StringComparer.OrdinalIgnoreCase)
            .Select(group => group
                .OrderByDescending(item => item.IsRunning)
                .ThenByDescending(item => item.RiskScore)
                .First())
            .ToList();
        lock (_persistenceGate)
        {
            if (snapshot.ObservedAt - _lastPersistedAt >= TimeSpan.FromSeconds(
                    options.ObservationPersistenceIntervalSeconds))
            {
                registry.UpsertObservations(observations, snapshot.ObservedAt);
                _lastPersistedAt = snapshot.ObservedAt;
                return registry.GetAll();
            }
        }

        var currentByPath = observations.ToDictionary(
            item => item.ExecutablePath,
            StringComparer.OrdinalIgnoreCase);
        var merged = registry.GetAll()
            .Select(item => currentByPath.TryGetValue(
                item.ExecutablePath,
                out var current)
                ? current with { FirstSeen = item.FirstSeen }
                : item with
                {
                    IsRunning = false,
                    ProcessId = null,
                    NetworkConnectionCount = 0,
                    DistinctRemoteAddressCount = 0
                })
            .ToList();
        merged.AddRange(observations.Where(item =>
            !merged.Any(existing => string.Equals(
                existing.ExecutablePath,
                item.ExecutablePath,
                StringComparison.OrdinalIgnoreCase))));
        return merged;
    }

    public IReadOnlyList<AgentGovernanceDto> GetRegistry() =>
        registry.GetAll();

    public AgentPolicy Authorize(string path)
    {
        var policy = policies.Load();
        policy.AuthorizedPaths.Add(path);
        policy.BlockedPaths.Remove(path);
        var result = policies.Save(policy);
        RecordPolicyChange("agent.trusted", path);
        return result;
    }

    public AgentPolicy Block(string path)
    {
        var policy = policies.Load();
        policy.BlockedPaths.Add(path);
        policy.AuthorizedPaths.Remove(path);
        var result = policies.Save(policy);
        RecordPolicyChange("agent.blocked", path);
        return result;
    }

    public AgentPolicy Unblock(string path)
    {
        var policy = policies.Load();
        policy.BlockedPaths.Remove(path);
        var result = policies.Save(policy);
        RecordPolicyChange("agent.unblocked", path);
        return result;
    }

    private AgentGovernanceDto BuildObservation(
        AgentIdentityDto identity,
        string path,
        bool isRunning,
        int? processId,
        IReadOnlyCollection<ConnectionTelemetry> connections,
        DateTimeOffset observedAt)
    {
        var policy = policies.Load();
        var explicitlyBlocked = policy.BlockedPaths.Contains(path);
        var networkAuthorized = policy.AuthorizedPaths.Contains(path);
        var status = explicitlyBlocked
            ? "blocked"
            : networkAuthorized || identity.TrustedPath
                ? "trusted"
                : "unknown";
        var publicConnections = connections
            .Where(connection => IsPublicAddress(connection.RemoteAddress))
            .ToList();
        var distinctRemoteAddresses = publicConnections
            .Select(connection => connection.RemoteAddress)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();
        var unusualPort = publicConnections.Any(connection =>
            connection.RemotePort > 0 &&
            connection.RemotePort is not 53 and not 80 and not 123 and not 443);
        var unusualNetwork =
            distinctRemoteAddresses >= options.UnusualRemoteAddressThreshold ||
            unusualPort;
        var userWritablePath = options.UserWritablePathMarkers.Any(marker =>
            path.Contains(marker, StringComparison.OrdinalIgnoreCase));

        var (riskScore, riskReason) =
            explicitlyBlocked && isRunning
                ? (options.BlockedRunningRiskScore,
                    "Blocked agent is running.")
                : unusualNetwork
                    ? (options.UnusualNetworkRiskScore,
                        "Agent has unusual public network activity.")
                    : status == "trusted" && identity.TrustedPath
                        ? (options.TrustedPathRiskScore,
                            "Known agent is running from a trusted path.")
                        : userWritablePath
                            ? (options.UserWritablePathRiskScore,
                                "Unknown or unapproved agent is running from a user-writable path.")
                            : (options.UnknownPathRiskScore,
                                "Agent path is not explicitly trusted.");
        var canEnforcePath =
            !identity.SharedHost &&
            Path.IsPathFullyQualified(path) &&
            !string.IsNullOrWhiteSpace(Path.GetExtension(path));

        return new AgentGovernanceDto(
            identity.AgentKey,
            identity.Name,
            path,
            identity.Vendor,
            status,
            observedAt,
            observedAt,
            isRunning,
            processId,
            connections.Count,
            distinctRemoteAddresses,
            connections.Count > 0 ? observedAt : null,
            riskScore,
            riskReason,
            networkAuthorized,
            canEnforcePath);
    }

    private static bool IsPublicAddress(string value)
    {
        if (!IPAddress.TryParse(value, out var address) ||
            IPAddress.IsLoopback(address))
        {
            return false;
        }

        if (address.AddressFamily ==
            System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            return bytes[0] != 10 &&
                   bytes[0] != 127 &&
                   !(bytes[0] == 169 && bytes[1] == 254) &&
                   !(bytes[0] == 172 && bytes[1] is >= 16 and <= 31) &&
                   !(bytes[0] == 192 && bytes[1] == 168);
        }

        return !address.IsIPv6LinkLocal &&
               !address.IsIPv6SiteLocal &&
               !address.Equals(IPAddress.IPv6Loopback);
    }

    private void RecordPolicyChange(string action, string path)
    {
        audit.Write(
            "Administrator",
            action,
            "agent_registry",
            path,
            true,
            System.Text.Json.JsonSerializer.Serialize(new { Path = path }));
        logs.Security(
            action,
            "AI agent policy changed.",
            new { Path = path });
    }
}
