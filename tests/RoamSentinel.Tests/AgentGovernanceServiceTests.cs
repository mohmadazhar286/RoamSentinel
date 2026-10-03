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

    [Fact]
    public void ClaudeCode_FromTrustedNpmPath_HasLowRisk()
    {
        var (service, _) = CreateService();
        var process = Process(
            15,
            "node",
            @"C:\npm\node_modules\@anthropic-ai\claude-code\cli.js");

        var result = service.Evaluate(process);

        Assert.True(result.IsAgent);
        Assert.Equal("Claude Code", result.AgentName);
        Assert.Equal("Anthropic", result.Vendor);
        Assert.Equal("trusted", result.Status);
        Assert.Equal(10, result.RiskScore);
    }

    [Fact]
    public void Antigravity_FromTrustedGeminiPath_HasLowRisk()
    {
        var (service, _) = CreateService();
        var process = Process(
            16,
            "agy",
            @"C:\Users\AM\.gemini\antigravity\bin\agy.exe");

        var result = service.Evaluate(process);

        Assert.True(result.IsAgent);
        Assert.Equal("Google Antigravity", result.AgentName);
        Assert.Equal("Google", result.Vendor);
        Assert.Equal("trusted", result.Status);
        Assert.Equal(10, result.RiskScore);
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
                true),
            new(
                "claude-code",
                "Claude Code",
                "Anthropic",
                ["@anthropic-ai/claude-code", "claude-code", "claude.cmd"],
                [@"\npm\node_modules\@anthropic-ai\claude-code", @"\appdata\roaming\npm\claude"],
                true),
            new(
                "antigravity",
                "Google Antigravity",
                "Google",
                ["antigravity", "agy", "@google/antigravity"],
                [@"\.gemini\antigravity", @"\appdata\local\programs\antigravity"],
                true),
            new(
                "mcp-server",
                "MCP Server",
                "Model Context Protocol",
                ["@modelcontextprotocol/server-", "mcp-server-", "mcp_server"],
                [@"\node_modules\@modelcontextprotocol"],
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

    [Fact]
    public void McpGovernance_DestructiveCommand_Blocks()
    {
        var repo = new InMemoryMcpTelemetryRepository();
        var service = new McpGovernanceService(repo);

        var request = new McpToolCallRequest(
            "claude-code",
            "bash-server",
            "execute_command",
            "{\"command\":\"rm -rf /\"}");

        var evt = service.AssessAndRecord(request, "tester");

        Assert.Equal("Block", evt.Verdict);
        Assert.Equal(90, evt.RiskScore);
        Assert.Equal("High", evt.Severity);
        Assert.Single(repo.Events);
    }

    [Fact]
    public void McpGovernance_SensitiveCredentials_Warns()
    {
        var repo = new InMemoryMcpTelemetryRepository();
        var service = new McpGovernanceService(repo);

        var request = new McpToolCallRequest(
            "antigravity",
            "filesystem-server",
            "read_file",
            "{\"path\":\"C:\\\\Users\\\\AM\\\\.ssh\\\\id_rsa\"}");

        var evt = service.AssessAndRecord(request, "tester");

        Assert.Equal("Warn", evt.Verdict);
        Assert.Equal(80, evt.RiskScore);
        Assert.Single(repo.Events);
    }

    [Fact]
    public void McpGovernance_SystemLocation_Blocks()
    {
        var repo = new InMemoryMcpTelemetryRepository();
        var service = new McpGovernanceService(repo);

        var request = new McpToolCallRequest(
            "goose-ai",
            "filesystem-server",
            "write_file",
            "{\"path\":\"C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts\"}");

        var evt = service.AssessAndRecord(request, "tester");

        Assert.Equal("Block", evt.Verdict);
        Assert.Equal(85, evt.RiskScore);
        Assert.Single(repo.Events);
    }

    [Fact]
    public void McpGovernance_SafeTool_Allows()
    {
        var repo = new InMemoryMcpTelemetryRepository();
        var service = new McpGovernanceService(repo);

        var request = new McpToolCallRequest(
            "antigravity",
            "search-server",
            "search_docs",
            "{\"query\":\"how to configure RoamSentinel\"}");

        var evt = service.AssessAndRecord(request, "tester");

        Assert.Equal("Allow", evt.Verdict);
        Assert.Equal(10, evt.RiskScore);
        Assert.Single(repo.Events);
    }

    private sealed class InMemoryMcpTelemetryRepository : IMcpTelemetryRepository
    {
        public List<McpToolCallEventDto> Events { get; } = [];

        public void RecordEvent(McpToolCallEventDto toolCall)
        {
            Events.Add(toolCall);
        }

        public IReadOnlyList<McpToolCallEventDto> GetRecentEvents(int limit)
        {
            return Events.Take(limit).ToList();
        }

        public McpAuditSummaryDto GetSummary(int recentLimit = 50)
        {
            var blocked = Events.Count(e => e.Verdict == "Block");
            var warned = Events.Count(e => e.Verdict == "Warn");
            var distinctServers = Events.Select(e => e.ServerName).Distinct().ToList();
            var distinctTools = Events.Select(e => e.ToolName).Distinct().ToList();
            return new McpAuditSummaryDto(
                DateTimeOffset.UtcNow,
                Events.Count,
                blocked,
                warned,
                distinctServers,
                distinctTools,
                Events.Take(recentLimit).ToList());
        }
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
