using System.Security.Cryptography;
using System.Text;
using RoamSentinel.Config;
using RoamSentinel.Core;

namespace RoamSentinel.Detection;

public sealed class DetectionEngine(
    IDetectionRuleRepository rules,
    IThreatIndicatorRepository threatIndicators,
    DetectionOptions options) : IDetectionEngine
{
    private static readonly HashSet<string> ValidSeverities =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "Info", "Low", "Medium", "High", "Critical"
        };
    private static readonly HashSet<string> ProtectedWindowsProcesses =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "System",
            "Registry",
            "smss",
            "csrss",
            "wininit",
            "services",
            "lsass",
            "svchost",
            "spoolsv",
            "winlogon",
            "fontdrvhost",
            "dwm",
            "MsMpEng"
        };

    public DetectionResultDto Evaluate(
        TelemetrySnapshot snapshot,
        AgentPolicy agentPolicy)
    {
        var suspiciousIps = threatIndicators.GetActiveSuspiciousIps(
            snapshot.ObservedAt);
        var findings = new List<DetectionFindingDto>();
        foreach (var rule in rules.GetAll().Where(rule => rule.Enabled))
        {
            findings.AddRange(EvaluateRule(
                rule,
                snapshot,
                agentPolicy,
                suspiciousIps));
        }

        var unique = findings
            .DistinctBy(
                finding => $"{finding.RuleId}|{finding.EntityType}|{finding.EntityId}",
                StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(finding => SeverityRank(finding.Severity))
            .ThenByDescending(finding => finding.RiskScore)
            .ThenBy(finding => finding.RuleName)
            .ToList();
        var overallScore = unique
            .GroupBy(finding => $"{finding.EntityType}|{finding.EntityId}")
            .Select(group => Math.Min(100, group.Sum(item => item.RiskScore)))
            .DefaultIfEmpty(0)
            .Max();

        return new DetectionResultDto(
            snapshot.ObservedAt,
            overallScore,
            SeverityForScore(overallScore),
            unique);
    }

    public ConnectionDto AssessConnection(
        ConnectionTelemetry connection,
        DetectionResultDto result)
    {
        var risk = RiskFor(
            result,
            "network",
            NetworkEntityId(connection));
        return new ConnectionDto(
            connection.Protocol,
            connection.LocalAddress,
            connection.LocalPort,
            connection.RemoteAddress,
            connection.RemotePort,
            connection.State,
            connection.ProcessId,
            connection.ProcessName,
            connection.ProcessPath,
            risk.Score,
            risk.Reason);
    }

    public ProcessDto AssessProcess(
        ProcessTelemetry process,
        AgentEvaluation agent,
        DetectionResultDto result)
    {
        var risk = RiskFor(
            result,
            "process",
            process.ProcessId.ToString());
        return new ProcessDto(
            process.ProcessId,
            process.Name,
            process.Path,
            process.MemoryMb,
            process.PrivateMemoryMb,
            process.CpuPercent,
            process.HandleCount,
            process.ThreadCount,
            process.ConnectionCount,
            process.StartedAt,
            risk.Score,
            risk.Reason,
            agent.IsAgent,
            agent.NetworkAuthorized);
    }

    public StartupEntryDto AssessStartup(
        StartupTelemetry startup,
        DetectionResultDto result)
    {
        var risk = RiskFor(result, "startup", StartupEntityId(startup));
        return new StartupEntryDto(
            startup.Name,
            startup.Command,
            startup.Source,
            risk.Score);
    }

    public IReadOnlyList<AlertDto> BuildAlerts(DetectionResultDto result) =>
        result.Findings.Select(finding => new AlertDto(
            finding.FindingId,
            finding.ObservedAt,
            finding.Category,
            finding.Severity,
            finding.Title,
            BuildAlertDetail(finding))).ToList();

    private IEnumerable<DetectionFindingDto> EvaluateRule(
        DetectionRuleDto rule,
        TelemetrySnapshot snapshot,
        AgentPolicy policy,
        IReadOnlySet<string> suspiciousIps) =>
        rule.RuleId switch
        {
            "RS-EXEC-001" => DetectEncodedPowerShell(rule, snapshot),
            "RS-PROC-002" => DetectTemporaryProcesses(rule, snapshot),
            "RS-NET-002" => DetectUnknownNetworkProcesses(rule, snapshot),
            "RS-PERSIST-001" => DetectStartupPersistence(rule, snapshot),
            "RS-PERSIST-002" => DetectScheduledTaskPersistence(rule, snapshot),
            "RS-PROC-001" => DetectUntrustedAgents(rule, snapshot, policy),
            "RS-AGENT-BLOCK-001" => DetectBlockedRunningAgents(
                rule,
                snapshot),
            "RS-AGENT-NET-001" => DetectUnusualAgentNetwork(
                rule,
                snapshot),
            "RS-NET-003" => DetectSuspiciousIpConnections(
                rule,
                snapshot,
                suspiciousIps),
            "RS-DEFENSE-001" => DetectDisabledDefender(rule, snapshot),
            "RS-DEFENSE-002" => DetectDisabledFirewall(rule, snapshot),
            _ => []
        };

    private IEnumerable<DetectionFindingDto> DetectEncodedPowerShell(
        DetectionRuleDto rule,
        TelemetrySnapshot snapshot) =>
        snapshot.Processes
            .Where(process =>
                IsPowerShell(process.Name, process.Path) &&
                HasEncodedCommand(process.CommandLine))
            .Select(process => Finding(
                rule,
                snapshot.ObservedAt,
                "PowerShell launched with encoded command",
                rule.Description,
                $"{process.Name} ({process.ProcessId}): " +
                Truncate(process.CommandLine, 512),
                "process",
                process.ProcessId.ToString()));

    private IEnumerable<DetectionFindingDto> DetectTemporaryProcesses(
        DetectionRuleDto rule,
        TelemetrySnapshot snapshot) =>
        snapshot.Processes
            .Where(process =>
                !string.IsNullOrWhiteSpace(process.Path) &&
                process.Path.Contains(
                    @"\temp\",
                    StringComparison.OrdinalIgnoreCase))
            .Select(process => Finding(
                rule,
                snapshot.ObservedAt,
                $"Executable running from Temp: {process.Name}",
                rule.Description,
                process.Path,
                "process",
                process.ProcessId.ToString()));

    private static IEnumerable<DetectionFindingDto>
        DetectUnknownNetworkProcesses(
            DetectionRuleDto rule,
            TelemetrySnapshot snapshot) =>
        snapshot.Processes
            .Where(process =>
                process.ProcessId > 4 &&
                process.ConnectionCount > 0 &&
                string.IsNullOrWhiteSpace(process.Path) &&
                !ProtectedWindowsProcesses.Contains(process.Name))
            .Select(process => Finding(
                rule,
                snapshot.ObservedAt,
                $"Network-active executable path unavailable: {process.Name}",
                rule.Description,
                $"PID {process.ProcessId}; connections: {process.ConnectionCount}",
                "process",
                process.ProcessId.ToString()));

    private IEnumerable<DetectionFindingDto> DetectStartupPersistence(
        DetectionRuleDto rule,
        TelemetrySnapshot snapshot) =>
        snapshot.StartupEntries
            .Where(item =>
                item.Source is not "Scheduled task" and
                not "Auto-start service" &&
                IsSuspiciousCommand(item.Command))
            .Select(item => Finding(
                rule,
                snapshot.ObservedAt,
                $"Suspicious startup entry: {item.Name}",
                rule.Description,
                $"{item.Source}: {item.Command}",
                "startup",
                StartupEntityId(item)));

    private IEnumerable<DetectionFindingDto> DetectScheduledTaskPersistence(
        DetectionRuleDto rule,
        TelemetrySnapshot snapshot) =>
        snapshot.ScheduledTasks
            .Where(task =>
                task.Enabled &&
                IsSuspiciousScheduledTask(task))
            .Select(task => Finding(
                rule,
                snapshot.ObservedAt,
                $"Suspicious scheduled task: {task.Name}",
                rule.Description,
                $"{task.Path}{task.Name}: {task.Command} {task.Arguments}".Trim(),
                "scheduled_task",
                $"{task.Path}|{task.Name}"));

    private static IEnumerable<DetectionFindingDto> DetectUntrustedAgents(
        DetectionRuleDto rule,
        TelemetrySnapshot snapshot,
        AgentPolicy policy)
    {
        if (snapshot.GovernedAgents is not null)
        {
            return snapshot.GovernedAgents
                .Where(agent =>
                    agent.IsRunning &&
                    agent.Status == "unknown")
                .Select(agent => Finding(
                    rule,
                    snapshot.ObservedAt,
                    $"AI agent running from untrusted path: {agent.Name}",
                    rule.Description,
                    $"{agent.ExecutablePath}; {agent.RiskReason}",
                    agent.ProcessId is null ? "agent" : "process",
                    agent.ProcessId?.ToString() ?? agent.ExecutablePath))
                .ToList();
        }

        return snapshot.InstalledAgents
            .Where(agent =>
                agent.IsRunning &&
                !string.IsNullOrWhiteSpace(agent.Path) &&
                !policy.AuthorizedPaths.Contains(agent.Path))
            .Select(agent => Finding(
                rule,
                snapshot.ObservedAt,
                $"AI agent running from untrusted path: {agent.Name}",
                rule.Description,
                agent.Path,
                agent.ProcessId is null ? "agent" : "process",
                agent.ProcessId?.ToString() ?? agent.Path))
            .ToList();
    }

    private static IEnumerable<DetectionFindingDto>
        DetectBlockedRunningAgents(
            DetectionRuleDto rule,
            TelemetrySnapshot snapshot) =>
        (snapshot.GovernedAgents ?? [])
            .Where(agent => agent.IsRunning && agent.Status == "blocked")
            .Select(agent => Finding(
                rule,
                snapshot.ObservedAt,
                $"Blocked AI agent is running: {agent.Name}",
                rule.Description,
                $"{agent.ExecutablePath}; PID {agent.ProcessId}",
                agent.ProcessId is null ? "agent" : "process",
                agent.ProcessId?.ToString() ?? agent.ExecutablePath));

    private static IEnumerable<DetectionFindingDto>
        DetectUnusualAgentNetwork(
            DetectionRuleDto rule,
            TelemetrySnapshot snapshot) =>
        (snapshot.GovernedAgents ?? [])
            .Where(agent =>
                agent.IsRunning &&
                agent.NetworkConnectionCount > 0 &&
                agent.RiskScore >= 80 &&
                agent.RiskReason.Contains(
                    "network",
                    StringComparison.OrdinalIgnoreCase))
            .Select(agent => Finding(
                rule,
                snapshot.ObservedAt,
                $"AI agent unusual network activity: {agent.Name}",
                rule.Description,
                $"{agent.NetworkConnectionCount} connection(s), " +
                $"{agent.DistinctRemoteAddressCount} public destination(s); " +
                agent.ExecutablePath,
                agent.ProcessId is null ? "agent" : "process",
                agent.ProcessId?.ToString() ?? agent.ExecutablePath));

    private static IEnumerable<DetectionFindingDto>
        DetectSuspiciousIpConnections(
            DetectionRuleDto rule,
            TelemetrySnapshot snapshot,
            IReadOnlySet<string> suspiciousIps) =>
        snapshot.Connections
            .Where(connection =>
                suspiciousIps.Contains(connection.RemoteAddress))
            .Select(connection => Finding(
                rule,
                snapshot.ObservedAt,
                $"Connection to suspicious IP: {connection.RemoteAddress}",
                rule.Description,
                $"{connection.ProcessName} ({connection.ProcessId}) -> " +
                $"{connection.RemoteAddress}:{connection.RemotePort}",
                "network",
                NetworkEntityId(connection)));

    private static IEnumerable<DetectionFindingDto> DetectDisabledDefender(
        DetectionRuleDto rule,
        TelemetrySnapshot snapshot)
    {
        if (snapshot.Defender.AntivirusEnabled &&
            snapshot.Defender.RealTimeProtectionEnabled)
        {
            return [];
        }

        return
        [
            Finding(
                rule,
                snapshot.ObservedAt,
                "Microsoft Defender protection disabled",
                rule.Description,
                snapshot.Defender.Message.Length > 0
                    ? snapshot.Defender.Message
                    : $"Antivirus={snapshot.Defender.AntivirusEnabled}; " +
                      $"RealTime={snapshot.Defender.RealTimeProtectionEnabled}",
                "security_control",
                "defender")
        ];
    }

    private static IEnumerable<DetectionFindingDto> DetectDisabledFirewall(
        DetectionRuleDto rule,
        TelemetrySnapshot snapshot)
    {
        if (!snapshot.Firewall.Available)
        {
            return [];
        }

        return snapshot.Firewall.Profiles
            .Where(profile => !profile.Enabled)
            .Select(profile => Finding(
                rule,
                snapshot.ObservedAt,
                $"Windows Firewall profile disabled: {profile.Name}",
                rule.Description,
                $"Profile={profile.Name}; inbound={profile.DefaultInboundAction}; " +
                $"outbound={profile.DefaultOutboundAction}",
                "security_control",
                $"firewall:{profile.Name}"));
    }

    private Risk RiskFor(
        DetectionResultDto result,
        string entityType,
        string entityId)
    {
        var matches = result.Findings
            .Where(finding =>
                string.Equals(
                    finding.EntityType,
                    entityType,
                    StringComparison.OrdinalIgnoreCase) &&
                string.Equals(
                    finding.EntityId,
                    entityId,
                    StringComparison.OrdinalIgnoreCase))
            .ToList();
        return new Risk(
            Math.Min(100, matches.Sum(finding => finding.RiskScore)),
            string.Join(
                "; ",
                matches.Select(finding => finding.RuleName).Distinct()));
    }

    private static DetectionFindingDto Finding(
        DetectionRuleDto rule,
        DateTimeOffset observedAt,
        string title,
        string description,
        string evidence,
        string entityType,
        string entityId)
    {
        var idInput =
            $"{rule.RuleId}|{entityType}|{entityId}|{title}|{evidence}";
        var findingId = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(idInput)))[..20];
        return new DetectionFindingDto(
            findingId,
            observedAt,
            rule.RuleId,
            rule.Name,
            rule.Category,
            NormalizeSeverity(rule.Severity),
            Math.Clamp(rule.RiskWeight, 0, 100),
            title,
            description,
            evidence,
            entityType,
            entityId,
            rule.MitreMappings);
    }

    private bool IsSuspiciousCommand(string command) =>
        IsUserWritable(command) ||
        options.ScriptableProcesses.Any(process =>
            command.Contains(process, StringComparison.OrdinalIgnoreCase));

    private bool IsSuspiciousScheduledTask(ScheduledTaskTelemetry task)
    {
        var command = $"{task.Command} {task.Arguments}";
        if (IsUserWritable(command))
        {
            return true;
        }

        return !task.Path.StartsWith(
                @"\Microsoft\Windows\",
                StringComparison.OrdinalIgnoreCase) &&
            options.ScriptableProcesses.Any(process =>
                command.Contains(process, StringComparison.OrdinalIgnoreCase));
    }

    private bool IsUserWritable(string value) =>
        options.UserWritablePathMarkers.Any(marker =>
            value.Contains(marker, StringComparison.OrdinalIgnoreCase));

    private static bool IsPowerShell(string name, string path) =>
        name.Equals("powershell", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("pwsh", StringComparison.OrdinalIgnoreCase) ||
        path.EndsWith(
            @"\powershell.exe",
            StringComparison.OrdinalIgnoreCase) ||
        path.EndsWith(@"\pwsh.exe", StringComparison.OrdinalIgnoreCase);

    private static bool HasEncodedCommand(string commandLine)
    {
        var arguments = commandLine
            .Split(' ', StringSplitOptions.RemoveEmptyEntries |
                        StringSplitOptions.TrimEntries);
        return arguments.Any(argument =>
            argument.Equals("-enc", StringComparison.OrdinalIgnoreCase) ||
            argument.Equals("/enc", StringComparison.OrdinalIgnoreCase) ||
            argument.Equals(
                "-encodedcommand",
                StringComparison.OrdinalIgnoreCase) ||
            argument.Equals(
                "/encodedcommand",
                StringComparison.OrdinalIgnoreCase));
    }

    private string SeverityForScore(int score) =>
        score >= options.CriticalSeverityScore
            ? "Critical"
            : score >= options.HighSeverityScore
                ? "High"
                : score >= options.MediumSeverityScore
                    ? "Medium"
                    : score >= options.LowSeverityScore
                        ? "Low"
                        : "Info";

    private static int SeverityRank(string severity) =>
        NormalizeSeverity(severity) switch
        {
            "Critical" => 4,
            "High" => 3,
            "Medium" => 2,
            "Low" => 1,
            _ => 0
        };

    private static string NormalizeSeverity(string severity) =>
        ValidSeverities.Contains(severity)
            ? char.ToUpperInvariant(severity[0]) +
              severity[1..].ToLowerInvariant()
            : "Info";

    private static string NetworkEntityId(ConnectionTelemetry connection) =>
        $"{connection.Protocol}|{connection.ProcessId}|" +
        $"{connection.RemoteAddress}|{connection.RemotePort}";

    private static string StartupEntityId(StartupTelemetry startup) =>
        $"{startup.Source}|{startup.Name}";

    private static string BuildAlertDetail(DetectionFindingDto finding)
    {
        var mappings = string.Join(
            ", ",
            finding.MitreMappings.Select(mapping =>
                $"{mapping.TechniqueId} {mapping.TechniqueName}"));
        return mappings.Length == 0
            ? finding.Evidence
            : $"{finding.Evidence}. MITRE ATT&CK: {mappings}";
    }

    private static string Truncate(string value, int maximumLength) =>
        value.Length <= maximumLength
            ? value
            : value[..maximumLength] + "...";
}
