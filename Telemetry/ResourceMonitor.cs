using System.Runtime.InteropServices;
using RoamSentinel.Core;

namespace RoamSentinel.Telemetry;

public sealed class ResourceMonitor : IResourceMonitor
{
    public MemoryDto GetMemory()
    {
        var status = new MemoryStatusEx
        {
            dwLength = (uint)Marshal.SizeOf<MemoryStatusEx>()
        };

        if (!GlobalMemoryStatusEx(ref status))
        {
            return new MemoryDto(0, 0, 0, 0);
        }

        var totalGb = Math.Round(status.ullTotalPhys / 1024d / 1024d / 1024d, 2);
        var availableGb = Math.Round(status.ullAvailPhys / 1024d / 1024d / 1024d, 2);
        var usedGb = Math.Round(totalGb - availableGb, 2);
        return new MemoryDto(totalGb, usedGb, availableGb, status.dwMemoryLoad);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GlobalMemoryStatusEx(ref MemoryStatusEx lpBuffer);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct MemoryStatusEx
    {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }
}
