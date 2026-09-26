using RoamSentinel.Core;

namespace RoamSentinel.AppActivity;

public sealed class AppActivityModule : IProductModule
{
    public ModuleRegistration Registration { get; } = new(
        "app-activity",
        "AppActivity",
        "Application usage and background behavior",
        "active",
        [
            "Installed application inventory",
            "Last seen running and network activity",
            "Auto-start/background activity correlation",
            "Unused but active recommendations"
        ]);
}
