using RoamSentinel.Core;

namespace RoamSentinel.MobileBridge;

public sealed class MobileBridgeModule : IProductModule
{
    public ModuleRegistration Registration { get; } = new(
        "mobile-bridge",
        "MobileBridge",
        "Mobile endpoint companion bridge",
        "active",
        [
            "Android companion pairing",
            "Mobile heartbeat telemetry",
            "Installed app inventory ingestion",
            "Mobile security finding ingestion",
            "PC dashboard readiness for mobile devices"
        ]);
}