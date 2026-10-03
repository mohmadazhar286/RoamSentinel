using System.Text.RegularExpressions;
using RoamSentinel.Core;

namespace RoamSentinel.AgentGovernance;

public sealed class McpGovernanceService(
    IMcpTelemetryRepository telemetryRepository,
    IEventRepository? eventRepository = null) : IMcpGovernanceService
{
    private static readonly Regex DestructiveCommands = new(
        @"(?i)(rm\s+-rf|remove-item\s+.*-recurse\s+.*-force|format-volume|diskpart|bcdedit|del\s+/[fs]|rd\s+/[sq]|takeown\s+/f|icacls\s+.*\s+/grant\s+everyone|-encodedcommand|frombase64string|iex\s*\(|invoke-expression|stop-service|disablerealtimemonitoring|curl\s+.*\|\s*(sh|bash|powershell|pwsh)|wget\s+.*\|\s*(sh|bash|powershell|pwsh)|iwr\s+.*\|\s*iex)",
        RegexOptions.Compiled,
        TimeSpan.FromSeconds(1));

    private static readonly Regex SensitiveFiles = new(
        @"(?i)(\.env\b|id_rsa\b|id_ed25519\b|id_ecdsa\b|\bcredentials\b|\bSAM\b|\bshadow\b|\bmaster\.key\b|appsettings\.production\.json\b|web\.config\b|client_secret)",
        RegexOptions.Compiled,
        TimeSpan.FromSeconds(1));

    private static readonly Regex SystemLocations = new(
        @"(?i)([\\/]+windows[\\/]+(system32|syswow64)|currentversion[\\/]+run)",
        RegexOptions.Compiled,
        TimeSpan.FromSeconds(1));

    public McpToolCallEventDto AssessAndRecord(
        McpToolCallRequest request,
        string actor)
    {
        ArgumentNullException.ThrowIfNull(request);

        var toolName = request.ToolName ?? "";
        var arguments = request.ArgumentsJson ?? "";
        var agentKey = string.IsNullOrWhiteSpace(request.AgentKey)
            ? "unknown-agent"
            : request.AgentKey;
        var serverName = string.IsNullOrWhiteSpace(request.ServerName)
            ? "default"
            : request.ServerName;

        var verdict = "Allow";
        var riskScore = 10;
        var severity = "Info";
        var policyReason = "MCP tool invocation evaluated and permitted within local policy.";

        if (IsExecutionTool(toolName) && DestructiveCommands.IsMatch(arguments))
        {
            verdict = "Block";
            riskScore = 90;
            severity = "High";
            policyReason = "Destructive shell, downloader, or system impairment command detected in MCP arguments.";
        }
        else if (IsSystemWriteTool(toolName) && SystemLocations.IsMatch(arguments))
        {
            verdict = "Block";
            riskScore = 85;
            severity = "High";
            policyReason = "Modification of protected Windows system location detected in MCP tool arguments.";
        }
        else if (IsReadTool(toolName) && SensitiveFiles.IsMatch(arguments))
        {
            verdict = "Warn";
            riskScore = 80;
            severity = "High";
            policyReason = "Sensitive credential or private key target detected in MCP arguments.";
        }

        var eventId = Guid.NewGuid().ToString("N");
        var eventDto = new McpToolCallEventDto(
            eventId,
            DateTimeOffset.UtcNow,
            agentKey,
            serverName,
            toolName,
            arguments,
            request.ResultSummary ?? "",
            riskScore,
            severity,
            verdict,
            policyReason,
            request.ProcessId,
            "127.0.0.1");

        telemetryRepository.RecordEvent(eventDto);

        if (verdict is "Block" or "Warn")
        {
            eventRepository?.TryAdd(new AlertDto(
                $"mcp-alert-{eventId}",
                eventDto.Timestamp,
                "Agent Governance",
                severity,
                $"AI agent '{agentKey}' attempted high-risk MCP tool '{toolName}'",
                $"{policyReason} Server: {serverName}, Verdict: {verdict}"));
        }

        return eventDto;
    }

    public IReadOnlyList<McpToolCallEventDto> GetRecentEvents(int limit) =>
        telemetryRepository.GetRecentEvents(limit);

    public McpAuditSummaryDto GetSummary(int recentLimit = 50) =>
        telemetryRepository.GetSummary(recentLimit);

    private static bool IsExecutionTool(string toolName) =>
        toolName.Contains("command", StringComparison.OrdinalIgnoreCase) ||
        toolName.Contains("bash", StringComparison.OrdinalIgnoreCase) ||
        toolName.Contains("shell", StringComparison.OrdinalIgnoreCase) ||
        toolName.Contains("terminal", StringComparison.OrdinalIgnoreCase) ||
        toolName.Contains("exec", StringComparison.OrdinalIgnoreCase) ||
        toolName.Contains("powershell", StringComparison.OrdinalIgnoreCase) ||
        toolName.Contains("run", StringComparison.OrdinalIgnoreCase);

    private static bool IsReadTool(string toolName) =>
        toolName.Contains("read", StringComparison.OrdinalIgnoreCase) ||
        toolName.Contains("fetch", StringComparison.OrdinalIgnoreCase) ||
        toolName.Contains("get", StringComparison.OrdinalIgnoreCase) ||
        toolName.Contains("cat", StringComparison.OrdinalIgnoreCase) ||
        toolName.Contains("open", StringComparison.OrdinalIgnoreCase);

    private static bool IsSystemWriteTool(string toolName) =>
        toolName.Contains("write", StringComparison.OrdinalIgnoreCase) ||
        toolName.Contains("edit", StringComparison.OrdinalIgnoreCase) ||
        toolName.Contains("delete", StringComparison.OrdinalIgnoreCase) ||
        toolName.Contains("modify", StringComparison.OrdinalIgnoreCase) ||
        toolName.Contains("create", StringComparison.OrdinalIgnoreCase) ||
        toolName.Contains("overwrite", StringComparison.OrdinalIgnoreCase);
}
