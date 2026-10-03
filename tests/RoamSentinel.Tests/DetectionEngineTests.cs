using RoamSentinel.Config;
using RoamSentinel.Core;
using RoamSentinel.Detection;

namespace RoamSentinel.Tests;

public sealed class DetectionEngineTests
{
    [Fact]
    public void Evaluate_DetectsRequiredBehaviorsWithMitreMappings()
    {
        var engine = CreateEngine();

        var result = engine.Evaluate(
            CreateSuspiciousSnapshot(),
            new AgentPolicy());

        var ruleIds = result.Findings
            .Select(finding => finding.RuleId)
            .ToHashSet();
        Assert.Equal(9, ruleIds.Count);
        foreach (var expected in RuleIds)
        {
            Assert.Contains(expected, ruleIds);
        }

        Assert.All(
            result.Findings,
            finding => Assert.NotEmpty(finding.MitreMappings));
        Assert.Contains(
            result.Findings,
            finding =>
                finding.RuleId == "RS-EXEC-001" &&
                finding.Severity == "Critical" &&
                finding.MitreMappings.Any(mapping =>
                    mapping.TechniqueId == "T1059.001"));
        Assert.Equal(100, result.OverallRiskScore);
        Assert.Equal("Critical", result.OverallSeverity);
    }

    [Fact]
    public void Evaluate_DisabledRuleDoesNotProduceFinding()
    {
        var rules = CreateRules()
            .Select(rule => rule.RuleId == "RS-EXEC-001"
                ? rule with { Enabled = false }
                : rule)
            .ToList();
        var engine = CreateEngine(rules);

        var result = engine.Evaluate(
            CreateSuspiciousSnapshot(),
            new AgentPolicy());

        Assert.DoesNotContain(
            result.Findings,
            finding => finding.RuleId == "RS-EXEC-001");
    }

    [Fact]
    public void AssessProcess_AccumulatesMatchedRuleWeights()
    {
        var snapshot = CreateSuspiciousSnapshot();
        var engine = CreateEngine();
        var result = engine.Evaluate(snapshot, new AgentPolicy());
        var process = snapshot.Processes.Single(item => item.ProcessId == 42);

        var assessed = engine.AssessProcess(
            process,
            new AgentEvaluation(false, false, false),
            result);

        Assert.Equal(100, assessed.RiskScore);
        Assert.Contains(
            "PowerShell encoded command",
            assessed.RiskReason);
        Assert.Contains(
            "temporary directory",
            assessed.RiskReason,
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Evaluate_AuthorizedAgentSuppressesUntrustedAgentRule()
    {
        var snapshot = CreateSuspiciousSnapshot();
        var policy = new AgentPolicy(
            [@"C:\Users\User\AppData\Roaming\codex.exe"],
            []);

        var result = CreateEngine().Evaluate(snapshot, policy);

        Assert.DoesNotContain(
            result.Findings,
            finding => finding.RuleId == "RS-PROC-001");
    }

    [Fact]
    public void Evaluate_DetectsBlockedAndUnusualNetworkAgents()
    {
        var rules = new[]
        {
            Rule(
                "RS-AGENT-BLOCK-001",
                "Blocked AI agent is running",
                "Agent Governance",
                "Critical",
                100,
                "T1204.002"),
            Rule(
                "RS-AGENT-NET-001",
                "AI agent unusual network activity",
                "Agent Governance",
                "High",
                80,
                "T1071")
        };
        var snapshot = CreateSuspiciousSnapshot() with
        {
            GovernedAgents =
            [
                new AgentGovernanceDto(
                    "cursor", "Cursor", @"C:\Tools\cursor.exe", "Anysphere",
                    "blocked", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow,
                    true, 50, 0, 0, null, 100,
                    "Blocked agent is running.", false, true),
                new AgentGovernanceDto(
                    "windsurf", "Windsurf", @"C:\Tools\windsurf.exe",
                    "Codeium", "trusted", DateTimeOffset.UtcNow,
                    DateTimeOffset.UtcNow, true, 51, 5, 3,
                    DateTimeOffset.UtcNow, 80,
                    "Agent has unusual public network activity.", true, true)
            ]
        };

        var result = CreateEngine(rules).Evaluate(snapshot, new AgentPolicy());

        Assert.Contains(
            result.Findings,
            item =>
                item.RuleId == "RS-AGENT-BLOCK-001" &&
                item.Severity == "Critical");
        Assert.Contains(
            result.Findings,
            item =>
                item.RuleId == "RS-AGENT-NET-001" &&
                item.Severity == "High");
    }

    [Fact]
    public void Evaluate_DetectsAgentSpawningSuspiciousChildProcess()
    {
        var rules = new[]
        {
            Rule(
                "RS-AGENT-CHILD-001",
                "AI agent spawned suspicious child process",
                "Agent Governance",
                "High",
                85,
                "T1059.001")
        };
        var snapshot = CreateSuspiciousSnapshot() with
        {
            GovernedAgents =
            [
                new AgentGovernanceDto(
                    "claude-code", "Claude Code", @"C:\npm\claude.cmd", "Anthropic",
                    "trusted", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow,
                    true, 100, 0, 0, null, 10,
                    "Agent is trusted.", true, true)
            ],
            Processes =
            [
                new ProcessTelemetry(
                    100, "claude", @"C:\npm\claude.cmd", 50, 40, 1.0, 10, 5, 0,
                    DateTimeOffset.UtcNow, 0, "", "claude"),
                new ProcessTelemetry(
                    101, "powershell", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    30, 25, 2.0, 10, 4, 0, DateTimeOffset.UtcNow,
                    100, "claude", "powershell.exe -enc SQBFAFgA..."),
                new ProcessTelemetry(
                    102, "git", @"C:\Program Files\Git\bin\git.exe",
                    20, 15, 0.5, 5, 2, 0, DateTimeOffset.UtcNow,
                    100, "claude", "git status")
            ]
        };

        var result = CreateEngine(rules).Evaluate(snapshot, new AgentPolicy());

        var finding = Assert.Single(result.Findings);
        Assert.Equal("RS-AGENT-CHILD-001", finding.RuleId);
        Assert.Equal("High", finding.Severity);
        Assert.Equal("process", finding.EntityType);
        Assert.Equal("101", finding.EntityId);
        Assert.Contains("Claude Code", finding.Evidence);
        Assert.Contains("powershell", finding.Evidence);
    }

    [Fact]
    public void Evaluate_DetectsAgentChildProcessDefenseImpairment()
    {
        var rules = new[]
        {
            Rule(
                "RS-AGENT-CHILD-001",
                "AI agent spawned suspicious child process",
                "Agent Governance",
                "High",
                85,
                "T1204.002")
        };
        var snapshot = CreateSuspiciousSnapshot() with
        {
            GovernedAgents =
            [
                new AgentGovernanceDto(
                    "antigravity", "Google Antigravity", @"C:\Tools\agy.exe", "Google",
                    "trusted", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow,
                    true, 200, 0, 0, null, 10,
                    "Agent is trusted.", true, true)
            ],
            Processes =
            [
                new ProcessTelemetry(
                    201, "cmd", @"C:\Windows\System32\cmd.exe",
                    15, 10, 0.5, 5, 2, 0, DateTimeOffset.UtcNow,
                    200, "agy", "cmd.exe /c sc stop WinDefend")
            ]
        };

        var result = CreateEngine(rules).Evaluate(snapshot, new AgentPolicy());

        var finding = Assert.Single(result.Findings);
        Assert.Equal("RS-AGENT-CHILD-001", finding.RuleId);
        Assert.Equal("201", finding.EntityId);
        Assert.Contains("sc stop WinDefend", finding.Evidence);
    }

    [Theory]
    [InlineData(19, "Info")]
    [InlineData(20, "Low")]
    [InlineData(44, "Low")]
    [InlineData(45, "Medium")]
    [InlineData(69, "Medium")]
    [InlineData(70, "High")]
    [InlineData(89, "High")]
    [InlineData(90, "Critical")]
    public void Evaluate_UsesConfiguredRiskScoreBoundaries(
        int riskWeight,
        string expectedSeverity)
    {
        var engine = CreateEngine(
        [
            Rule(
                "RS-DEFENSE-001",
                "Microsoft Defender disabled",
                "Defense Impairment",
                "Critical",
                riskWeight,
                "T1562.001")
        ]);

        var result = engine.Evaluate(
            CreateSuspiciousSnapshot(),
            new AgentPolicy());

        Assert.Equal(riskWeight, result.OverallRiskScore);
        Assert.Equal(expectedSeverity, result.OverallSeverity);
    }

    private static DetectionEngine CreateEngine(
        IReadOnlyList<DetectionRuleDto>? configuredRules = null) =>
        new(
            new InMemoryRuleRepository(configuredRules ?? CreateRules()),
            new InMemoryThreatIndicatorRepository(
                new HashSet<string> { "203.0.113.10" }),
            new DetectionOptions());

    private static TelemetrySnapshot CreateSuspiciousSnapshot()
    {
        var observedAt = DateTimeOffset.UtcNow;
        return new TelemetrySnapshot(
            observedAt,
            [
                new ConnectionTelemetry(
                    "TCP",
                    "10.0.0.2",
                    50000,
                    "203.0.113.10",
                    443,
                    "Established",
                    42,
                    "powershell",
                    @"C:\Users\User\AppData\Local\Temp\powershell.exe")
            ],
            [
                new ProcessTelemetry(
                    42,
                    "powershell",
                    @"C:\Users\User\AppData\Local\Temp\powershell.exe",
                    100,
                    90,
                    2,
                    50,
                    8,
                    1,
                    observedAt,
                    10,
                    "parent",
                    "powershell.exe -EncodedCommand SQBFAFgA"),
                new ProcessTelemetry(
                    43,
                    "unknown",
                    "",
                    10,
                    8,
                    0,
                    5,
                    2,
                    1,
                    observedAt)
            ],
            [
                new StartupTelemetry(
                    "Updater",
                    @"powershell.exe C:\Users\User\AppData\Roaming\run.ps1",
                    @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run")
            ],
            [
                new ScheduledTaskTelemetry(
                    "Updater",
                    "\\",
                    "Ready",
                    true,
                    "user",
                    "powershell.exe",
                    @"C:\Users\User\AppData\Roaming\run.ps1",
                    "Logon")
            ],
            [],
            new DefenderStatusDto(
                true, false, false, true, 1, 2, observedAt, "1", ""),
            new FirewallStatusDto(
                true,
                true,
                [
                    new FirewallProfileTelemetry(
                        "Public", false, "Block", "Allow", false)
                ],
                ""),
            [
                new AgentInstallationTelemetry(
                    "Codex",
                    @"C:\Users\User\AppData\Roaming\codex.exe",
                    "1",
                    "OpenAI",
                    "Running process",
                    true,
                    44)
            ],
            []);
    }

    private static IReadOnlyList<DetectionRuleDto> CreateRules() =>
        new[]
        {
            Rule("RS-EXEC-001", "PowerShell encoded command", "Execution",
                "Critical", 90, "T1059.001"),
            Rule("RS-PROC-002", "Executable launched from temporary directory",
                "Execution", "High", 65, "T1204.002"),
            Rule("RS-NET-002", "Unknown executable with network activity",
                "Network", "Medium", 45, "T1071"),
            Rule("RS-PERSIST-001", "Suspicious startup persistence",
                "Persistence", "High", 60, "T1547.001"),
            Rule("RS-PERSIST-002", "Suspicious scheduled task persistence",
                "Persistence", "High", 70, "T1053.005"),
            Rule("RS-PROC-001", "AI agent executing from untrusted path",
                "Agent Governance", "High", 80, "T1204.002"),
            Rule("RS-NET-003", "Process connected to suspicious IP",
                "Threat Intelligence", "Critical", 95, "T1071"),
            Rule("RS-DEFENSE-001", "Microsoft Defender disabled",
                "Defense Impairment", "Critical", 100, "T1685"),
            Rule("RS-DEFENSE-002", "Windows Firewall profile disabled",
                "Defense Impairment", "Critical", 95, "T1686.003")
        };

    private static DetectionRuleDto Rule(
        string id,
        string name,
        string category,
        string severity,
        int weight,
        string technique) =>
        new(
            id,
            name,
            $"{name} description",
            category,
            true,
            severity,
            weight,
            80,
            "{}",
            [new MitreMappingDto(
                category,
                technique,
                name,
                technique.Contains('.') ? technique : null)]);

    private static readonly string[] RuleIds =
    [
        "RS-EXEC-001",
        "RS-PROC-002",
        "RS-NET-002",
        "RS-PERSIST-001",
        "RS-PERSIST-002",
        "RS-PROC-001",
        "RS-NET-003",
        "RS-DEFENSE-001",
        "RS-DEFENSE-002"
    ];

    private sealed class InMemoryRuleRepository(
        IReadOnlyList<DetectionRuleDto> configuredRules)
        : IDetectionRuleRepository
    {
        public IReadOnlyList<DetectionRuleDto> GetAll() => configuredRules;

        public DetectionRuleDto? SetEnabled(string ruleId, bool enabled) =>
            throw new NotSupportedException();
    }

    private sealed class InMemoryThreatIndicatorRepository(
        IReadOnlySet<string> indicators) : IThreatIndicatorRepository
    {
        public IReadOnlySet<string> GetActiveSuspiciousIps(
            DateTimeOffset asOf) => indicators;

        public IReadOnlyList<ThreatIndicatorDto> GetAll(int limit) => [];

        public ThreatIndicatorDto? FindActive(
            string indicator,
            string indicatorType,
            string source,
            DateTimeOffset asOf) => null;

        public ThreatIndicatorDto Upsert(
            ThreatIndicatorDto indicator,
            string actor) => indicator;

        public bool RemoveLocal(
            string indicator,
            string indicatorType) => false;
    }
}
