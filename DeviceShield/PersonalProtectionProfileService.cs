using RoamSentinel.Core;

namespace RoamSentinel.DeviceShield;

public sealed class PersonalProtectionProfileService :
    IPersonalProtectionProfileService
{
    public PersonalProtectionProfileDto GetProfile() => new(
        DateTimeOffset.UtcNow,
        "PersonalProtectionMinimal",
        "Single Windows workstation, VM, or server operated by the local owner.",
        [
            Control(
                "pp-defender-scan",
                "Malware",
                "Microsoft Defender scan launch",
                "available",
                "Operator-approved quick, full, deep, or file scan through RS response hooks.",
                "Run scans from RS Console when suspicious activity is observed."),
            Control(
                "pp-firewall-ip-block",
                "Network",
                "Windows Firewall IP block/restore",
                "available",
                "Administrator-approved outbound and inbound block rules with local restore metadata.",
                "Block only reviewed public IPs; do not block loopback or local infrastructure."),
            Control(
                "pp-agent-network-control",
                "AI agent governance",
                "AI/dev agent network control by executable path",
                "available",
                "Reviewable allow/block policy for detected agent executables.",
                "Authorize only known local agent binaries that require network access."),
            Control(
                "pp-device-integrity",
                "Device integrity",
                "Baseline change visibility",
                "available",
                "Service-collected inventory and findings for startup, service, task, firewall, listener, driver, software, registry, and PowerShell posture changes.",
                "Review new findings weekly and mark expected changes explicitly."),
            Control(
                "pp-codegate-staging",
                "Deployment gate",
                "CodeGate staging deployment gate",
                "available",
                "Offline scan of staging folders, Git pushes, ZIP/imported code, deployment scripts, dependency manifests, and risky app artifacts.",
                "Run CodeGate before deploying local or university VM applications."),
            Control(
                "pp-mobile-pairing",
                "Companion telemetry",
                "MobileBridge local pairing",
                "preview",
                "Temporary QR/code enrollment and token-based heartbeat/inventory/finding submission.",
                "Use only for local companion testing until a signed Android client exists."),
            Control(
                "pp-autonomous-remediation",
                "Response safety",
                "Autonomous destructive remediation",
                "not-enabled",
                "RS does not delete, quarantine, or kill without authenticated operator action.",
                "Keep this disabled for personal devices until restore paths are proven.")
        ]);

    private static PersonalProtectionControlDto Control(
        string id,
        string category,
        string name,
        string status,
        string enforcement,
        string operatorAction) =>
        new(id, category, name, status, enforcement, operatorAction);
}
