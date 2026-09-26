using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using RoamSentinel.Core;

namespace RoamSentinel.Telemetry;

public sealed class ProcessTelemetryCollector
{
    private const uint SnapshotProcesses = 0x00000002;
    private static readonly IntPtr InvalidHandle = new(-1);
    private readonly ConcurrentDictionary<int, CpuSample> _cpuSamples = new();

    public IReadOnlyList<ProcessTelemetry> Collect(
        IReadOnlyCollection<ConnectionTelemetry> connections)
    {
        var connectionCounts = connections
            .GroupBy(connection => connection.ProcessId)
            .ToDictionary(group => group.Key, group => group.Count());
        var parentIds = ReadParentProcessIds();
        var names = Process.GetProcesses()
            .Select(process =>
            {
                try
                {
                    return (Id: process.Id, ProcessName: process.ProcessName);
                }
                catch
                {
                    return (Id: 0, ProcessName: "");
                }
                finally
                {
                    process.Dispose();
                }
            })
            .Where(item => item.Id > 0)
            .ToDictionary(item => item.Id, item => item.ProcessName);

        return Process.GetProcesses()
            .Select(process => ReadProcess(
                process,
                connectionCounts.GetValueOrDefault(process.Id),
                parentIds.GetValueOrDefault(process.Id),
                names))
            .Where(process => process is not null)
            .Cast<ProcessTelemetry>()
            .ToList();
    }

    private ProcessTelemetry? ReadProcess(
        Process process,
        int connectionCount,
        int parentProcessId,
        IReadOnlyDictionary<int, string> processNames)
    {
        using (process)
        {
            try
            {
                return new ProcessTelemetry(
                    process.Id,
                    process.ProcessName,
                    TryGetPath(process),
                    Math.Round(process.WorkingSet64 / 1024d / 1024d, 1),
                    Math.Round(process.PrivateMemorySize64 / 1024d / 1024d, 1),
                    GetCpuPercent(process),
                    TryGetHandleCount(process),
                    TryGetThreadCount(process),
                    connectionCount,
                    TryGetStartTime(process),
                    parentProcessId,
                    processNames.GetValueOrDefault(parentProcessId) ?? "",
                    "");
            }
            catch
            {
                return null;
            }
        }
    }

    private double GetCpuPercent(Process process)
    {
        try
        {
            var now = DateTimeOffset.UtcNow;
            var total = process.TotalProcessorTime;
            if (!_cpuSamples.TryGetValue(process.Id, out var previous))
            {
                _cpuSamples[process.Id] = new CpuSample(total, now);
                return 0;
            }

            _cpuSamples[process.Id] = new CpuSample(total, now);
            var elapsedMs = (now - previous.Timestamp).TotalMilliseconds;
            var cpuMs = (total - previous.TotalProcessorTime).TotalMilliseconds;
            if (elapsedMs <= 0 || cpuMs < 0)
            {
                return 0;
            }

            var percent = cpuMs / elapsedMs / Environment.ProcessorCount * 100d;
            return double.IsFinite(percent)
                ? Math.Round(Math.Min(percent, 100), 1)
                : 0;
        }
        catch
        {
            return 0;
        }
    }

    private static Dictionary<int, int> ReadParentProcessIds()
    {
        var parents = new Dictionary<int, int>();
        if (!OperatingSystem.IsWindows())
        {
            return parents;
        }

        var snapshot = CreateToolhelp32Snapshot(SnapshotProcesses, 0);
        if (snapshot == InvalidHandle)
        {
            return parents;
        }

        try
        {
            var entry = new ProcessEntry32
            {
                Size = (uint)Marshal.SizeOf<ProcessEntry32>()
            };
            if (!Process32First(snapshot, ref entry))
            {
                return parents;
            }

            do
            {
                parents[(int)entry.ProcessId] = (int)entry.ParentProcessId;
            }
            while (Process32Next(snapshot, ref entry));
        }
        finally
        {
            CloseHandle(snapshot);
        }

        return parents;
    }

    private static string TryGetPath(Process process)
    {
        try { return process.MainModule?.FileName ?? ""; }
        catch { return ""; }
    }

    private static int TryGetHandleCount(Process process)
    {
        try { return process.HandleCount; }
        catch { return 0; }
    }

    private static int TryGetThreadCount(Process process)
    {
        try { return process.Threads.Count; }
        catch { return 0; }
    }

    private static DateTimeOffset? TryGetStartTime(Process process)
    {
        try { return process.StartTime; }
        catch { return null; }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public uint Size;
        public uint Usage;
        public uint ProcessId;
        public IntPtr DefaultHeapId;
        public uint ModuleId;
        public uint Threads;
        public uint ParentProcessId;
        public int BasePriority;
        public uint Flags;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string ExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32First(
        IntPtr snapshot,
        ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32Next(
        IntPtr snapshot,
        ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
