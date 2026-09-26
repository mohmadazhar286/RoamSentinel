using RoamSentinel.Core;

namespace RoamSentinel.Config;

public static class PolicyCatalog
{
    public static readonly PolicyRuleDto[] ActivePolicies =
    [
        new("Local dashboard", "RoamSentinel binds to loopback only."),
        new("Agent exception", "AI/dev agent executable paths are unapproved until authorized."),
        new("Agent block", "Blocked agent paths receive RoamSentinel outbound Windows Firewall rules."),
        new("IP block", "Blocked remote IPs receive inbound and outbound Windows Firewall rules."),
        new("Log review", "Alert and action logs persist until the review purge action is used."),
        new("Persistence scan", "Unreadable protected scheduled-task folders are skipped and readable task commands are checked.")
    ];
}
