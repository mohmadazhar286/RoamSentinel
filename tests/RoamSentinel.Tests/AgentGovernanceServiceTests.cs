using RoamSentinel.AgentGovernance;
using RoamSentinel.Config;
using RoamSentinel.Core;
using RoamSentinel.Logs;

namespace RoamSentinel.Tests;

public sealed class AgentGovernanceServiceTests
{
    [Fact]
    public void TrustedAgentFromTrustedPath_HasLowRisk()
    {
        var (service, _) = CreateService();
        var process = Process(
            7,
            "Cursor",
            @"C:\Users\User\AppData\Local\Programs\Cursor\Cursor.exe");

        var result = service.Evaluate(process);

        Assert.True(result.IsAgent);
        Assert.Equal("Cursor", result.AgentName);
        Assert.Equal("Anysphere", result.Vendor);
        Assert.Equal("trusted", result.Status);
        Assert.Equal(10, result.RiskScore);
    }

    [Fact]
    public void UnknownAgentFromTemporaryPath_HasHighRisk()
    {
        var (service, _) = CreateService();

        var result = service.Evaluate(Process(
            8,
            "Codex",
            @"C:\Users\User\Downloads\codex.exe"));

        Assert.Equal("unknown", result.Status);
        Assert.Equal(70, result.RiskScore);
        Assert.Contains("user-writable", result.RiskReason);
    }

    [Fact]
    public void BlockedRunningAgent_IsCritical()
    {
        var (service, _) = CreateService();
        const string path = @"C:\Tools\cursor.exe";
        service.Block(path);

        var result = service.Evaluate(Process(9, "Cursor", path));

        Assert.True(result.ExplicitlyBlocked);
        Assert.Equal("blocked", result.Status);
        Assert.Equal(100, result.RiskScore);
    }

    [Fact]
    public void UnusualAgentNetworkActivity_IsHighRisk()
    {
        var (service, _) = CreateService();
        var process = Process(
            10,
            "Cursor",
            @"C:\Users\User\AppData\Local\Programs\Cursor\Cursor.exe");
        var connections = new[]
        {
            new ConnectionTelemetry(
                "TCP", "10.0.0.2", 50000, "203.0.113.10", 4444,
                "Established", 10, process.Name, process.Path)
        };

        var result = service.Evaluate(process, connections);

        Assert.Equal("trusted", result.Status);
        Assert.Equal(80, result.RiskScore);
        Assert.Contains("network", result.RiskReason);
    }

    [Fact]
    public void AuthorizeAndUnblock_PreserveRegistryHistory()
    {
        var (service, repository) = CreateService();
        const string path = @"C:\Tools\cursor.exe";
        service.Authorize(path);
        service.Block(path);
        service.Unblock(path);

        Assert.DoesNotContain(path, service.GetPolicy().AuthorizedPaths);
        Assert.DoesNotContain(path, service.GetPolicy().BlockedPaths);
        Assert.Contains(path, repository.SeenPolicyPaths);
    }

    private static (
        AgentGovernanceService Service,
        InMemoryAgentRepository Repository) CreateService()
    {
        var repository = new InMemoryAgentRepository();
        var options = new AgentGovernanceOptions();
        var identities = new AgentIdentityService(repository, options);
        return (
            new AgentGovernanceService(
                repository,
                repository,
                identities,
                options,
                new NoOpAuditRepository(),
                NullStructuredLogService.Instance),
            repository);
    }

    private static ProcessTelemetry Process(
        int processId,
        string name,
        string path) =>
        new(
            processId,
            name,
            path,
            50,
            45,
            0,
            10,
            3,
            1,
            DateTimeOffset.UtcNow);

    private sealed class InMemoryAgentRepository
        : IAgentPolicyRepository, IAgentRegistryRepository
    {
        private AgentPolicy _policy = new();
        private readonly List<AgentGovernanceDto> _agents = [];

        public HashSet<string> SeenPolicyPaths { get; } =
            new(StringComparer.OrdinalIgnoreCase);

        public AgentPolicy Load() =>
            new(_policy.AuthorizedPaths, _policy.BlockedPaths);

        public AgentPolicy Save(AgentPolicy policy)
        {
            foreach (var path in _policy.AuthorizedPaths
                         .Concat(_policy.BlockedPaths)
                         .Concat(policy.AuthorizedPaths)
                         .Concat(policy.BlockedPaths))
            {
                SeenPolicyPaths.Add(path);
            }

            _policy = new AgentPolicy(
                policy.AuthorizedPaths,
                policy.BlockedPaths);
            return Load();
        }

        public IReadOnlyList<AgentDefinitionDto> GetDefinitions() =>
        [
            new(
                "cursor",
                "Cursor",
                "Anysphere",
                ["cursor"],
                [@"\appdata\local\programs\cursor\"],
                false),
            new(
                "codex",
                "Codex",
                "OpenAI",
                ["codex"],
                [@"\appdata\local\openai\codex"],
                true)
        ];

        public void UpsertObservations(
            IReadOnlyCollection<AgentGovernanceDto> agents,
            DateTimeOffset observedAt)
        {
            _agents.Clear();
            _agents.AddRange(agents);
        }

        public IReadOnlyList<AgentGovernanceDto> GetAll() => _agents;
    }

    private sealed class NoOpAuditRepository : IAuditRepository
    {
        public void Write(
            string actor,
            string action,
            string entityType,
            string entityId,
            bool success,
            string detailJson)
        {
        }

        public IReadOnlyList<AuditLogEntryDto> GetRecent(int limit) => [];
    }
}
