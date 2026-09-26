using System.Security.Principal;
using RoamSentinel.Core;

namespace RoamSentinel.App.Security;

public sealed class WindowsPrivilegeService : IPrivilegeService
{
    public bool IsAdministrator()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity)
            .IsInRole(WindowsBuiltInRole.Administrator);
    }
}
