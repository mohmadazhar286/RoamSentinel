using RoamSentinel.Core;

namespace RoamSentinel.DeviceShield;

public sealed class DeviceShieldModule : IProductModule
{
    public ModuleRegistration Registration { get; } = new(
        "rs-agent",
        "Device Shield",
        "RS Agent",
        "active",
        [
            "process-anomaly-detection",
            "startup-persistence-detection",
            "network-anomaly-detection",
            "suspicious-file-activity",
            "ransomware-behavior-indicators",
            "response-hooks",
            "personal-protection-minimal-profile"
        ]);
}
