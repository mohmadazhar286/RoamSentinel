using System.Text.Json;
using RoamSentinel.Core;

namespace RoamSentinel.Database;

public sealed class McpTelemetryRepository(
    IDatabaseConnectionFactory connections) : IMcpTelemetryRepository
{
    public void RecordEvent(McpToolCallEventDto toolCall)
    {
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO mcp_tool_events (
                event_id, timestamp, agent_key, server_name, tool_name,
                arguments_json, result_summary, risk_score, severity,
                verdict, policy_reason, process_id, client_host
            ) VALUES (
                $eventId, $timestamp, $agentKey, $serverName, $toolName,
                $argumentsJson, $resultSummary, $riskScore, $severity,
                $verdict, $policyReason, $processId, $clientHost
            )
            ON CONFLICT(event_id) DO UPDATE SET
                result_summary = excluded.result_summary,
                risk_score = excluded.risk_score,
                severity = excluded.severity,
                verdict = excluded.verdict,
                policy_reason = excluded.policy_reason;
            """;
        command.Parameters.AddWithValue("$eventId", toolCall.EventId);
        command.Parameters.AddWithValue(
            "$timestamp",
            toolCall.Timestamp.ToUniversalTime().ToString("O"));
        command.Parameters.AddWithValue("$agentKey", toolCall.AgentKey);
        command.Parameters.AddWithValue("$serverName", toolCall.ServerName);
        command.Parameters.AddWithValue("$toolName", toolCall.ToolName);
        command.Parameters.AddWithValue("$argumentsJson", toolCall.ArgumentsJson);
        command.Parameters.AddWithValue("$resultSummary", toolCall.ResultSummary);
        command.Parameters.AddWithValue("$riskScore", toolCall.RiskScore);
        command.Parameters.AddWithValue("$severity", toolCall.Severity);
        command.Parameters.AddWithValue("$verdict", toolCall.Verdict);
        command.Parameters.AddWithValue("$policyReason", toolCall.PolicyReason);
        command.Parameters.AddWithValue(
            "$processId",
            toolCall.ProcessId.HasValue ? toolCall.ProcessId.Value : DBNull.Value);
        command.Parameters.AddWithValue("$clientHost", toolCall.ClientHost);
        command.ExecuteNonQuery();

        AuditSql.Insert(
            connection,
            transaction,
            toolCall.AgentKey,
            "agent_mcp.tool_called",
            "mcp_tool_event",
            toolCall.EventId,
            toolCall.Verdict != "Block",
            JsonSerializer.Serialize(new
            {
                toolCall.EventId,
                toolCall.AgentKey,
                toolCall.ServerName,
                toolCall.ToolName,
                toolCall.Verdict,
                toolCall.RiskScore,
                toolCall.Severity
            }));
        transaction.Commit();
    }

    public IReadOnlyList<McpToolCallEventDto> GetRecentEvents(int limit)
    {
        using var connection = connections.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT event_id, timestamp, agent_key, server_name, tool_name,
                   arguments_json, result_summary, risk_score, severity,
                   verdict, policy_reason, process_id, client_host
            FROM mcp_tool_events
            ORDER BY timestamp DESC
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 1000));
        using var reader = command.ExecuteReader();
        var results = new List<McpToolCallEventDto>();
        while (reader.Read())
        {
            results.Add(new McpToolCallEventDto(
                reader.GetString(0),
                DateTimeOffset.Parse(reader.GetString(1)),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetString(4),
                reader.GetString(5),
                reader.GetString(6),
                reader.GetInt32(7),
                reader.GetString(8),
                reader.GetString(9),
                reader.GetString(10),
                reader.IsDBNull(11) ? null : reader.GetInt32(11),
                reader.GetString(12)));
        }

        return results;
    }

    public McpAuditSummaryDto GetSummary(int recentLimit = 50)
    {
        var recent = GetRecentEvents(recentLimit);
        using var connection = connections.OpenConnection();

        using var countCmd = connection.CreateCommand();
        countCmd.CommandText = """
            SELECT
                COUNT(*),
                COALESCE(SUM(CASE WHEN verdict = 'Block' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN verdict = 'Warn' THEN 1 ELSE 0 END), 0)
            FROM mcp_tool_events;
            """;
        using var countReader = countCmd.ExecuteReader();
        countReader.Read();
        var total = countReader.GetInt32(0);
        var blocked = countReader.GetInt32(1);
        var warned = countReader.GetInt32(2);

        using var serverCmd = connection.CreateCommand();
        serverCmd.CommandText = "SELECT DISTINCT server_name FROM mcp_tool_events ORDER BY server_name;";
        using var serverReader = serverCmd.ExecuteReader();
        var servers = new List<string>();
        while (serverReader.Read())
        {
            servers.Add(serverReader.GetString(0));
        }

        using var toolCmd = connection.CreateCommand();
        toolCmd.CommandText = "SELECT DISTINCT tool_name FROM mcp_tool_events ORDER BY tool_name;";
        using var toolReader = toolCmd.ExecuteReader();
        var tools = new List<string>();
        while (toolReader.Read())
        {
            tools.Add(toolReader.GetString(0));
        }

        return new McpAuditSummaryDto(
            DateTimeOffset.UtcNow,
            total,
            blocked,
            warned,
            servers,
            tools,
            recent);
    }
}
