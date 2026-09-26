using Microsoft.Win32;
using RoamSentinel.Core;

namespace RoamSentinel.Telemetry;

public sealed class StartupTelemetryCollector
{
    public IReadOnlyList<StartupTelemetry> Collect()
    {
        var entries = new List<StartupTelemetry>();
        ReadRunKey(
            entries,
            Registry.CurrentUser,
            "HKCU",
            @"Software\Microsoft\Windows\CurrentVersion\Run");
        ReadRunKey(
            entries,
            Registry.LocalMachine,
            "HKLM",
            @"Software\Microsoft\Windows\CurrentVersion\Run");
        AddFolder(
            entries,
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            "Current user startup folder");
        AddFolder(
            entries,
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
            "All users startup folder");
        return entries
            .OrderBy(entry => entry.Source)
            .ThenBy(entry => entry.Name)
            .ToList();
    }

    private static void ReadRunKey(
        ICollection<StartupTelemetry> entries,
        RegistryKey hive,
        string hiveName,
        string path)
    {
        try
        {
            using var key = hive.OpenSubKey(path);
            if (key is null)
            {
                return;
            }

            foreach (var name in key.GetValueNames())
            {
                entries.Add(new StartupTelemetry(
                    name,
                    key.GetValue(name)?.ToString() ?? "",
                    $"{hiveName}\\{path}"));
            }
        }
        catch
        {
            // Protected registry keys are skipped without aborting the snapshot.
        }
    }

    private static void AddFolder(
        ICollection<StartupTelemetry> entries,
        string folder,
        string source)
    {
        if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder))
        {
            return;
        }

        try
        {
            foreach (var file in Directory.EnumerateFiles(folder))
            {
                entries.Add(new StartupTelemetry(
                    Path.GetFileName(file),
                    file,
                    source));
            }
        }
        catch
        {
            // Inaccessible startup entries are skipped.
        }
    }
}
