using System.Text.Json;
using RoamSentinel.Config;
using RoamSentinel.Core;

namespace RoamSentinel.Telemetry;

public sealed class DeviceIntegrityInventoryService(
    IPowerShellRunner powerShell,
    TelemetryOptions options) : IDeviceIntegrityInventoryService
{
    private const string Script = """
        $configured = @();
        try {
            $configured = @(
                ConvertFrom-Json $env:ROAMSENTINEL_PARAM_MONITORED_PATHS
            );
        } catch {}
        $paths = @(
            [Environment]::GetFolderPath('Startup'),
            [Environment]::GetFolderPath('CommonStartup')
        ) + $configured;
        $paths = @($paths | Where-Object {
            -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_)
        } | Select-Object -Unique);

        $drivers = @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
            Select-Object Name,DisplayName,State,StartMode,PathName,ServiceType);

        $software = @();
        foreach ($root in @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )) {
            $software += @(Get-ItemProperty $root -ErrorAction SilentlyContinue |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_.DisplayName) } |
                Select-Object DisplayName,DisplayVersion,Publisher,InstallLocation,
                    @{n='RegistrySource';e={$root}});
        }

        $persistence = @();
        foreach ($item in @(
            @{ Hive='HKLM'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' },
            @{ Hive='HKLM'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' },
            @{ Hive='HKCU'; Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' },
            @{ Hive='HKCU'; Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' },
            @{ Hive='HKLM'; Path='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' }
        )) {
            $key = Get-ItemProperty -LiteralPath $item.Path -ErrorAction SilentlyContinue;
            if ($null -ne $key) {
                foreach ($property in $key.PSObject.Properties |
                    Where-Object { $_.Name -notlike 'PS*' }) {
                    $persistence += [pscustomobject]@{
                        Hive=$item.Hive; Key=$item.Path;
                        Name=$property.Name; Value=[string]$property.Value
                    };
                }
            }
        }

        $files = @($paths | ForEach-Object {
            Get-ChildItem -LiteralPath $_ -File -Recurse -Force -ErrorAction SilentlyContinue
        } | Select-Object -First ([int]$env:ROAMSENTINEL_PARAM_FILE_LIMIT) |
            Select-Object FullName,Length,LastWriteTimeUtc,Extension);

        $services = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
            Select-Object Name,DisplayName,State,StartMode,PathName,ProcessId,StartName);

        $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
            $task = $_;
            $action = @($task.Actions | Select-Object -First 1);
            $trigger = @($task.Triggers | Select-Object -First 1);
            [pscustomobject]@{
                Name=$task.TaskName;
                Path=$task.TaskPath;
                State=[string]$task.State;
                Enabled=($task.Settings.Enabled -ne $false);
                Author=[string]$task.Author;
                Command=[string]$action.Execute;
                Arguments=[string]$action.Arguments;
                Trigger=[string]$trigger.ToString()
            }
        });

        $firewall = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue |
            Select-Object Name,Enabled,DefaultInboundAction,
                DefaultOutboundAction,NotifyOnListen);

        $tcpListeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Select-Object @{n='Protocol';e={'TCP'}},LocalAddress,LocalPort,OwningProcess);
        $udpListeners = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
            Select-Object @{n='Protocol';e={'UDP'}},LocalAddress,LocalPort,OwningProcess);
        $listeners = @($tcpListeners + $udpListeners | ForEach-Object {
            $processName = '';
            $processPath = '';
            try {
                $process = Get-Process -Id $_.OwningProcess -ErrorAction Stop;
                $processName = [string]$process.ProcessName;
                try { $processPath = [string]$process.MainModule.FileName; } catch {}
            } catch {}
            [pscustomobject]@{
                Protocol=[string]$_.Protocol;
                LocalAddress=[string]$_.LocalAddress;
                LocalPort=[int]$_.LocalPort;
                ProcessId=[int]$_.OwningProcess;
                ProcessName=$processName;
                ProcessPath=$processPath
            }
        });

        $policy = Get-ExecutionPolicy;
        $loggingRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell';
        $scriptBlock = Get-ItemProperty "$loggingRoot\ScriptBlockLogging" -ErrorAction SilentlyContinue;
        $module = Get-ItemProperty "$loggingRoot\ModuleLogging" -ErrorAction SilentlyContinue;
        $transcription = Get-ItemProperty "$loggingRoot\Transcription" -ErrorAction SilentlyContinue;
        $ps = [pscustomobject]@{
            ExecutionPolicy=[string]$policy;
            ScriptBlockLogging=([int]$scriptBlock.EnableScriptBlockLogging -eq 1);
            ModuleLogging=([int]$module.EnableModuleLogging -eq 1);
            Transcription=([int]$transcription.EnableTranscripting -eq 1);
            Version=[string]$PSVersionTable.PSVersion
        };

        [pscustomobject]@{
            Drivers=$drivers;
            Software=$software;
            Persistence=$persistence;
            Files=$files;
            Services=$services;
            ScheduledTasks=$tasks;
            FirewallProfiles=$firewall;
            NetworkListeners=$listeners;
            PowerShell=$ps
        } | ConvertTo-Json -Depth 6 -Compress
        """;

    public async Task<DeviceIntegritySnapshot> CollectAsync(
        CancellationToken cancellationToken = default)
    {
        var result = await powerShell.RunAsync(
            new PowerShellCommand(
                Script,
                new Dictionary<string, string>
                {
                    ["MONITORED_PATHS"] = JsonSerializer.Serialize(
                        options.MonitoredFileDirectories),
                    ["FILE_LIMIT"] = options.DeviceIntegrityFileLimit.ToString()
                }),
            TimeSpan.FromSeconds(
                options.DeviceIntegrityCommandTimeoutSeconds),
            cancellationToken);
        if (result.ExitCode != 0)
        {
            return Empty(result.Error);
        }

        try
        {
            using var document = JsonDocument.Parse(result.Output);
            var root = document.RootElement;
            return new DeviceIntegritySnapshot(
                DateTimeOffset.UtcNow,
                ReadArray(root, "Drivers", item => new DriverInventoryTelemetry(
                    Text(item, "Name"),
                    Text(item, "DisplayName"),
                    Text(item, "State"),
                    Text(item, "StartMode"),
                    Text(item, "PathName"),
                    Text(item, "ServiceType"))),
                ReadArray(root, "Software", item => new InstalledSoftwareTelemetry(
                    Text(item, "DisplayName"),
                    Text(item, "DisplayVersion"),
                    Text(item, "Publisher"),
                    Text(item, "InstallLocation"),
                    Text(item, "RegistrySource")))
                    .DistinctBy(item => $"{item.Name}|{item.Version}|{item.Publisher}")
                    .OrderBy(item => item.Name)
                    .ToList(),
                ReadArray(root, "Persistence", item => new RegistryPersistenceTelemetry(
                    Text(item, "Hive"),
                    Text(item, "Key"),
                    Text(item, "Name"),
                    Text(item, "Value"))),
                ReadArray(root, "Files", item => new FileInventoryTelemetry(
                    Text(item, "FullName"),
                    Number(item, "Length"),
                    Date(item, "LastWriteTimeUtc"),
                    Text(item, "Extension"))),
                ReadArray(root, "Services", item => new ServiceTelemetry(
                    Text(item, "Name"),
                    Text(item, "DisplayName"),
                    Text(item, "State"),
                    Text(item, "StartMode"),
                    Text(item, "PathName"),
                    Int(item, "ProcessId"),
                    Text(item, "StartName"))),
                ReadArray(root, "ScheduledTasks", item => new ScheduledTaskTelemetry(
                    Text(item, "Name"),
                    Text(item, "Path"),
                    Text(item, "State"),
                    Flag(item, "Enabled"),
                    Text(item, "Author"),
                    Text(item, "Command"),
                    Text(item, "Arguments"),
                    Text(item, "Trigger"))),
                ReadArray(root, "FirewallProfiles", item => new FirewallProfileTelemetry(
                    Text(item, "Name"),
                    Flag(item, "Enabled"),
                    Text(item, "DefaultInboundAction"),
                    Text(item, "DefaultOutboundAction"),
                    !Flag(item, "NotifyOnListen"))),
                ReadArray(root, "NetworkListeners", item => new LocalNetworkListenerTelemetry(
                    Text(item, "Protocol"),
                    Text(item, "LocalAddress"),
                    Int(item, "LocalPort"),
                    Int(item, "ProcessId"),
                    Text(item, "ProcessName"),
                    Text(item, "ProcessPath"))),
                ReadPowerShell(root),
                []);
        }
        catch (Exception exception)
        {
            return Empty(exception.Message);
        }
    }

    private static DeviceIntegritySnapshot Empty(string error) =>
        new(
            DateTimeOffset.UtcNow,
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            new("", false, false, false, ""),
            [string.IsNullOrWhiteSpace(error) ? "Inventory unavailable." : error]);

    private static PowerShellSecurityTelemetry ReadPowerShell(JsonElement root)
    {
        if (!root.TryGetProperty("PowerShell", out var value) ||
            value.ValueKind != JsonValueKind.Object)
        {
            return new("", false, false, false, "");
        }

        return new(
            Text(value, "ExecutionPolicy"),
            Flag(value, "ScriptBlockLogging"),
            Flag(value, "ModuleLogging"),
            Flag(value, "Transcription"),
            Text(value, "Version"));
    }

    private static IReadOnlyList<T> ReadArray<T>(
        JsonElement root,
        string property,
        Func<JsonElement, T> map)
    {
        if (!root.TryGetProperty(property, out var value))
        {
            return [];
        }

        return Enumerate(value)
            .Where(item => item.ValueKind == JsonValueKind.Object)
            .Select(map)
            .ToList();
    }

    private static IEnumerable<JsonElement> Enumerate(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in value.EnumerateArray())
            {
                yield return item;
            }
        }
        else if (value.ValueKind == JsonValueKind.Object)
        {
            yield return value;
        }
    }

    private static string Text(JsonElement item, string property) =>
        item.TryGetProperty(property, out var value)
            ? value.ToString()
            : "";

    private static bool Flag(JsonElement item, string property) =>
        item.TryGetProperty(property, out var value) &&
        value.ValueKind == JsonValueKind.True;

    private static long Number(JsonElement item, string property) =>
        item.TryGetProperty(property, out var value) &&
        value.TryGetInt64(out var number)
            ? number
            : 0;

    private static int Int(JsonElement item, string property) =>
        item.TryGetProperty(property, out var value) &&
        value.TryGetInt32(out var number)
            ? number
            : 0;

    private static DateTimeOffset Date(JsonElement item, string property) =>
        item.TryGetProperty(property, out var value) &&
        DateTimeOffset.TryParse(value.ToString(), out var date)
            ? date
            : DateTimeOffset.MinValue;
}
