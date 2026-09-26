using RoamSentinel.Core;

namespace RoamSentinel.DeviceShield;

public sealed class DataEgressModule : IProductModule
{
    public ModuleRegistration Registration { get; } = new(
        "data-egress",
        "Data Egress Monitor",
        "Application data-flow visibility",
        "active",
        [
            "Per-process outbound connection inventory",
            "Executable path and app correlation",
            "Unapproved app/network activity review",
            "Future WFP/ETW byte-count and DNS correlation readiness"
        ]);
}
