using RoamSentinel.Core;

namespace RoamSentinel.DeviceShield;

public sealed class ProtectionSchedulerModule : IProductModule
{
    public ModuleRegistration Registration { get; } = new(
        "protection-scheduler",
        "Protection Scheduler",
        "RS Agent",
        "active",
        [
            "background telemetry snapshot cadence",
            "app activity refresh cadence",
            "malware posture refresh cadence",
            "scheduled Defender scan readiness",
            "weekly operator review reminder"
        ]);
}
