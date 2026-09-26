using RoamSentinel.Core;

namespace RoamSentinel.App.Modules;

public sealed class ModuleExperienceService(
    IEnumerable<IProductModule> modules) : IModuleExperienceService
{
    public ModuleExperienceManifestDto GetManifest()
    {
        var registrations = modules
            .Select(module => module.Registration)
            .ToDictionary(
                registration => registration.Id,
                StringComparer.OrdinalIgnoreCase);
        var experiences = BuildExperiences(registrations);
        var workspaces = BuildWorkspaces(experiences);

        return new ModuleExperienceManifestDto(
            "1.0",
            DateTimeOffset.UtcNow,
            workspaces,
            experiences);
    }

    private static IReadOnlyList<ModuleExperienceDto> BuildExperiences(
        IReadOnlyDictionary<string, ModuleRegistration> registrations) =>
        [
            Experience(
                registrations,
                "rs-agent",
                "Device Shield",
                "RS Agent",
                "protect",
                "overview",
                ["overview", "deviceIntegrity", "malwareGuard", "processes", "connections", "alerts"],
                ["/api/dashboard/security-overview", "/api/v1/device-integrity", "/api/dashboard/malware-guard"],
                ["/api/actions/scan", "/api/actions/block-ip"],
                "Endpoint posture, integrity, malware, process, and network protection experience."),
            Experience(
                registrations,
                "protection-scheduler",
                "Protection Scheduler",
                "RS Agent",
                "respond",
                "responseHistory",
                ["overview", "settings", "responseHistory"],
                ["/api/v1/scheduler", "/api/dashboard/scheduler"],
                [],
                "Background task cadence, health, and operator review reminder experience."),
            Experience(
                registrations,
                "rs-codegate",
                "CodeGate",
                "RS CodeGate",
                "codegate",
                "components",
                ["components"],
                ["/api/v1/codegate/submissions", "/api/v1/codegate/git-pushes", "/api/v1/codegate/offline-bundles"],
                ["/api/modules/codegate/scan", "/api/v1/codegate/scan-path", "/api/v1/codegate/git-push"],
                "Pre-trust code intake, staging gate, Git push, and deployment evidence experience."),
            Experience(
                registrations,
                "data-egress",
                "Data Egress",
                "RS Agent",
                "protect",
                "connections",
                ["connections", "agents", "auditLog"],
                ["/api/dashboard/network-connections", "/api/dashboard/ai-agent-governance"],
                ["/api/actions/enforce-agent-policy", "/api/actions/block-agent"],
                "App, agent, and outbound data movement review experience."),
            Experience(
                registrations,
                "mobile-bridge",
                "MobileBridge",
                "RS Agent",
                "devices",
                "mobileDevices",
                ["mobileDevices"],
                ["/api/dashboard/mobile-devices", "/api/mobile-bridge"],
                ["/api/mobile-bridge/pairing-sessions"],
                "Companion device pairing, posture, app inventory, and finding intake experience."),
            Experience(
                registrations,
                "app-activity",
                "App Activity",
                "RS Agent",
                "protect",
                "appActivity",
                ["appActivity"],
                ["/api/dashboard/app-activity"],
                [],
                "Installed app, running app, and app data-use review experience."),
            Experience(
                registrations,
                "malware-guard",
                "MalwareGuard",
                "RS Agent",
                "protect",
                "malwareGuard",
                ["malwareGuard"],
                ["/api/dashboard/malware-guard"],
                ["/api/actions/scan", "/api/actions/scan-file"],
                "Microsoft Defender-backed scan, threat history, and suspicious file evidence experience."),
            Experience(
                registrations,
                "rs-insider",
                "Insider Risk",
                "RS Insider",
                "govern",
                "components",
                ["components", "auditLog"],
                ["/api/modules/insider-risk", "/api/dashboard/audit-log"],
                [],
                "User and device risk scoring foundation for future insider-risk workflows.")
        ];

    private static IReadOnlyList<ModuleWorkspaceDto> BuildWorkspaces(
        IReadOnlyList<ModuleExperienceDto> experiences) =>
        [
            Workspace(
                "protect",
                "Protect",
                "Device posture, app activity, malware protection, network, and findings.",
                "overview",
                experiences),
            Workspace(
                "codegate",
                "CodeGate",
                "Deployment, Git push, staged code, and package trust review.",
                "components",
                experiences),
            Workspace(
                "devices",
                "Devices",
                "PC integrity and companion/mobile device posture.",
                "mobileDevices",
                experiences),
            Workspace(
                "govern",
                "Govern",
                "Agents, insider-risk foundations, audit, policy, and administration.",
                "agents",
                experiences),
            new(
                "respond",
                "Respond",
                "Operator-approved response evidence and recovery history.",
                "responseHistory",
                [],
                ["responseHistory"]),
            new(
                "admin",
                "Admin",
                "Local settings, policy, audit, and system configuration.",
                "settings",
                [],
                ["settings", "auditLog"])
        ];

    private static ModuleExperienceDto Experience(
        IReadOnlyDictionary<string, ModuleRegistration> registrations,
        string id,
        string fallbackName,
        string fallbackComponent,
        string workspace,
        string defaultView,
        IReadOnlyList<string> views,
        IReadOnlyList<string> readEndpoints,
        IReadOnlyList<string> writeEndpoints,
        string description)
    {
        registrations.TryGetValue(id, out var registration);
        return new ModuleExperienceDto(
            id,
            registration?.Name ?? fallbackName,
            registration?.ProductComponent ?? fallbackComponent,
            workspace,
            defaultView,
            views,
            readEndpoints,
            writeEndpoints,
            registration?.Capabilities ?? [],
            "single-runtime-isolated-contract",
            description);
    }

    private static ModuleWorkspaceDto Workspace(
        string id,
        string label,
        string summary,
        string defaultView,
        IReadOnlyList<ModuleExperienceDto> experiences)
    {
        var modules = experiences
            .Where(experience => experience.Workspace == id)
            .Select(experience => experience.ModuleId)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        var views = experiences
            .Where(experience => experience.Workspace == id)
            .SelectMany(experience => experience.Views)
            .Append(defaultView)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        return new(id, label, summary, defaultView, modules, views);
    }
}
