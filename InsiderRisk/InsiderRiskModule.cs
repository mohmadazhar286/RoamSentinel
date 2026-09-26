using RoamSentinel.Core;

namespace RoamSentinel.InsiderRisk;

public sealed class InsiderRiskModule : IProductModule
{
    public ModuleRegistration Registration { get; } = new(
        "rs-insider",
        "Insider Risk",
        "RS Insider",
        "active",
        [
            "user-activity-baseline",
            "unusual-file-access",
            "unusual-login",
            "mass-copy-download",
            "suspicious-admin-activity",
            "user-device-risk-score"
        ]);
}

public sealed class InsiderRiskService(
    IAuditRepository audit,
    IEventRepository events,
    IResponseActionRepository responses,
    IAgentRegistryRepository agents) : IInsiderRiskService
{
    public InsiderRiskSummaryDto GetSummary()
    {
        var signals = new List<string>();
        var risk = 0;

        var auditEntries = audit.GetRecent(200);
        var failedAuth = auditEntries.Count(entry =>
            !entry.Success &&
            entry.Action.Contains(
                "authentication",
                StringComparison.OrdinalIgnoreCase));
        if (failedAuth > 0)
        {
            signals.Add($"{failedAuth} failed local authentication attempt(s).");
            risk += Math.Min(30, failedAuth * 10);
        }

        var deniedOrFailedResponses = responses.GetRecent(100)
            .Count(action => !action.Success);
        if (deniedOrFailedResponses > 0)
        {
            signals.Add(
                $"{deniedOrFailedResponses} denied or failed response action(s).");
            risk += Math.Min(25, deniedOrFailedResponses * 5);
        }

        var highAlerts = events.GetRecent(100).Count(alert =>
            alert.Severity.Equals("High", StringComparison.OrdinalIgnoreCase) ||
            alert.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase));
        if (highAlerts > 0)
        {
            signals.Add($"{highAlerts} high or critical security event(s).");
            risk += Math.Min(30, highAlerts * 6);
        }

        var riskyAgents = agents.GetAll().Count(agent =>
            agent.IsRunning &&
            (agent.Status.Equals("blocked", StringComparison.OrdinalIgnoreCase) ||
             agent.RiskScore >= 70));
        if (riskyAgents > 0)
        {
            signals.Add($"{riskyAgents} risky AI/developer agent(s) are running.");
            risk += Math.Min(35, riskyAgents * 12);
        }

        if (signals.Count == 0)
        {
            signals.Add("No elevated insider-risk signal in the local review window.");
        }

        risk = Math.Clamp(risk, 0, 100);
        return new InsiderRiskSummaryDto(
            DateTimeOffset.UtcNow,
            risk,
            risk >= 80 ? "critical" :
                risk >= 60 ? "high" :
                risk >= 30 ? "medium" :
                risk > 0 ? "low" : "info",
            signals);
    }
}
