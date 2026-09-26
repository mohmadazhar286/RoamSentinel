using System.Diagnostics;
using System.Security.Principal;
using System.Text.Json;
using RoamSentinel.Config;
using RoamSentinel.Core;

namespace RoamSentinel.Telemetry;

public sealed class WindowsTelemetryService(
    IPowerShellRunner powerShell,
    ProcessTelemetryCollector processes,
    StartupTelemetryCollector startup,
    AgentInstallationCollector agents,
    TelemetryOptions options) : ITelemetryService
{
    public async Task<IReadOnlyList<ConnectionTelemetry>> GetConnectionsAsync(
        CancellationToken cancellationToken = default)
    {
        const string command = """
            $tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object @{n='Protocol';e={'TCP'}},LocalAddress,LocalPort,RemoteAddress,RemotePort,@{n='State';e={$_.State.ToString()}},OwningProcess;
            $udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object @{n='Protocol';e={'UDP'}},LocalAddress,LocalPort,@{n='RemoteAddress';e={''}},@{n='RemotePort';e={0}},@{n='State';e={'Listening'}},OwningProcess;
            @(@($tcp) + @($udp)) | ConvertTo-Json -Depth 4
            """;

        var result = await RunAsync(
            command,
            options.ConnectionCommandTimeoutSeconds,
            cancellationToken);
        return ParseArray(result, ReadConnection);
    }

    public IReadOnlyList<ProcessTelemetry> GetProcesses(
        IReadOnlyCollection<ConnectionTelemetry> connections) =>
        processes.Collect(connections);

    public async Task<IReadOnlyDictionary<int, ProcessMetadataTelemetry>>
        GetProcessMetadataAsync(
            CancellationToken cancellationToken = default)
    {
        const string command = """
            Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
                Select-Object ProcessId,ParentProcessId,CommandLine |
                ConvertTo-Json -Depth 3
            """;
        var result = await RunAsync(
            command,
            options.InventoryCommandTimeoutSeconds,
            cancellationToken);
        return ParseArray(result, element => new ProcessMetadataTelemetry(
                GetInt(element, "ProcessId"),
                GetInt(element, "ParentProcessId"),
                GetString(element, "CommandLine")))
            .Where(item => item.ProcessId > 0)
            .ToDictionary(item => item.ProcessId);
    }

    public IReadOnlyList<StartupTelemetry> GetStartupEntries() =>
        startup.Collect();

    public async Task<IReadOnlyList<ScheduledTaskTelemetry>> GetScheduledTasksAsync(
        CancellationToken cancellationToken = default)
    {
        const string command = """
            Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
                [pscustomobject]@{
                    Name = $_.TaskName
                    Path = $_.TaskPath
                    State = $_.State.ToString()
                    Enabled = [bool]$_.Settings.Enabled
                    Author = [string]$_.Author
                    Command = [string](($_.Actions | ForEach-Object { $_.Execute }) -join '; ')
                    Arguments = [string](($_.Actions | ForEach-Object { $_.Arguments }) -join '; ')
                    Trigger = [string](($_.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join '; ')
                }
            } | ConvertTo-Json -Depth 4
            """;

        var result = await RunAsync(
            command,
            options.InventoryCommandTimeoutSeconds,
            cancellationToken);
        return ParseArray(result, element => new ScheduledTaskTelemetry(
            GetString(element, "Name"),
            GetString(element, "Path"),
            GetString(element, "State"),
            GetBool(element, "Enabled"),
            GetString(element, "Author"),
            GetString(element, "Command"),
            GetString(element, "Arguments"),
            GetString(element, "Trigger")));
    }

    public async Task<IReadOnlyList<ServiceTelemetry>> GetServicesAsync(
        CancellationToken cancellationToken = default)
    {
        const string command = """
            Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
                Select-Object Name,DisplayName,State,StartMode,PathName,ProcessId,StartName |
                ConvertTo-Json -Depth 4
            """;

        var result = await RunAsync(
            command,
            options.InventoryCommandTimeoutSeconds,
            cancellationToken);
        return ParseArray(result, element => new ServiceTelemetry(
            GetString(element, "Name"),
            GetString(element, "DisplayName"),
            GetString(element, "State"),
            GetString(element, "StartMode"),
            GetString(element, "PathName"),
            GetInt(element, "ProcessId"),
            GetString(element, "StartName")));
    }

    public async Task<DefenderStatusDto> GetDefenderStatusAsync(
        CancellationToken cancellationToken = default)
    {
        const string command = """
            Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,NISEnabled,QuickScanAge,FullScanAge,AntivirusSignatureLastUpdated,AntivirusSignatureVersion | ConvertTo-Json -Depth 3
            """;

        var result = await RunAsync(
            command,
            options.DefenderCommandTimeoutSeconds,
            cancellationToken);
        if (string.IsNullOrWhiteSpace(result))
        {
            return new DefenderStatusDto(
                false, false, false, false, null, null, null, "", 
                "Microsoft Defender status is unavailable.");
        }

        try
        {
            using var document = JsonDocument.Parse(result);
            var root = document.RootElement;
            return new DefenderStatusDto(
                GetBool(root, "AMServiceEnabled"),
                GetBool(root, "AntivirusEnabled"),
                GetBool(root, "RealTimeProtectionEnabled"),
                GetBool(root, "NISEnabled"),
                GetNullableInt(root, "QuickScanAge"),
                GetNullableInt(root, "FullScanAge"),
                GetNullableDate(root, "AntivirusSignatureLastUpdated"),
                GetString(root, "AntivirusSignatureVersion"),
                "");
        }
        catch (Exception ex)
        {
            return new DefenderStatusDto(
                false, false, false, false, null, null, null, "", ex.Message);
        }
    }

    public async Task<FirewallStatusDto> GetFirewallStatusAsync(
        CancellationToken cancellationToken = default)
    {
        const string command = """
            Get-NetFirewallProfile -ErrorAction SilentlyContinue |
                Select-Object Name,
                    @{n='Enabled';e={[bool]$_.Enabled}},
                    @{n='DefaultInboundAction';e={$_.DefaultInboundAction.ToString()}},
                    @{n='DefaultOutboundAction';e={$_.DefaultOutboundAction.ToString()}},
                    @{n='NotifyOnListen';e={[bool]$_.NotifyOnListen}} |
                ConvertTo-Json -Depth 3
            """;

        var result = await RunAsync(
            command,
            options.InventoryCommandTimeoutSeconds,
            cancellationToken);
        var profiles = ParseArray(result, element => new FirewallProfileTelemetry(
            GetString(element, "Name"),
            GetBool(element, "Enabled"),
            GetString(element, "DefaultInboundAction"),
            GetString(element, "DefaultOutboundAction"),
            !GetBool(element, "NotifyOnListen")));
        return profiles.Count == 0
            ? new FirewallStatusDto(
                false, false, [], "Windows Firewall status is unavailable.")
            : new FirewallStatusDto(
                true,
                profiles.Any(profile => profile.Enabled),
                profiles,
                "");
    }

    public IReadOnlyList<AgentInstallationTelemetry> GetInstalledAgents(
        IReadOnlyCollection<ProcessTelemetry> processItems) =>
        agents.Collect(processItems);

    public IReadOnlyList<SuspiciousPathTelemetry> GetSuspiciousPaths(
        IReadOnlyCollection<ProcessTelemetry> processItems,
        IReadOnlyCollection<StartupTelemetry> startupEntries,
        IReadOnlyCollection<ScheduledTaskTelemetry> scheduledTasks,
        IReadOnlyCollection<ServiceTelemetry> services,
        IReadOnlyCollection<AgentInstallationTelemetry> installedAgents) =>
        agents.FindSuspiciousPaths(
            processItems,
            startupEntries,
            scheduledTasks,
            services,
            installedAgents);

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

    private async Task<string> RunAsync(
        string command,
        int timeoutSeconds,
        CancellationToken cancellationToken)
    {
        var result = await powerShell.RunAsync(
            new PowerShellCommand(command),
            TimeSpan.FromSeconds(timeoutSeconds),
            cancellationToken);
        return result.ExitCode == 0 ? result.Output : "";
    }

    private static ConnectionTelemetry ReadConnection(JsonElement element)
    {
        var processId = GetInt(element, "OwningProcess");
        return new ConnectionTelemetry(
            GetString(element, "Protocol"),
            GetString(element, "LocalAddress"),
            GetInt(element, "LocalPort"),
            GetString(element, "RemoteAddress"),
            GetInt(element, "RemotePort"),
            GetString(element, "State"),
            processId,
            TryGetProcessName(processId),
            TryGetProcessPath(processId));
    }

    private static IReadOnlyList<T> ParseArray<T>(
        string json,
        Func<JsonElement, T> transform)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }

        try
        {
            using var document = JsonDocument.Parse(json);
            return EnumerateObjects(document.RootElement)
                .Select(transform)
                .ToList();
        }
        catch
        {
            return [];
        }
    }

    private static IEnumerable<JsonElement> EnumerateObjects(JsonElement root)
    {
        if (root.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in root.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.Object)
                {
                    yield return item;
                }
            }
        }
        else if (root.ValueKind == JsonValueKind.Object)
        {
            yield return root;
        }
    }

    private static string TryGetProcessName(int processId)
    {
        try
        {
            return processId > 0
                ? Process.GetProcessById(processId).ProcessName
                : "System";
        }
        catch
        {
            return "Unknown";
        }
    }

    private static string TryGetProcessPath(int processId)
    {
        try
        {
            return processId > 0
                ? Process.GetProcessById(processId).MainModule?.FileName ?? ""
                : "";
        }
        catch
        {
            return "";
        }
    }

    private static string GetString(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var value))
        {
            return "";
        }

        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString() ?? "",
            JsonValueKind.Number => value.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => ""
        };
    }

    private static int GetInt(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) &&
        int.TryParse(value.ToString(), out var result)
            ? result
            : 0;

    private static int? GetNullableInt(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) &&
        int.TryParse(value.ToString(), out var result)
            ? result
            : null;

    private static bool GetBool(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) &&
        value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.String =>
                bool.TryParse(value.GetString(), out var parsed) && parsed,
            JsonValueKind.Number =>
                value.TryGetInt32(out var number) && number != 0,
            _ => false
        };

    private static DateTimeOffset? GetNullableDate(
        JsonElement element,
        string property) =>
        element.TryGetProperty(property, out var value) &&
        DateTimeOffset.TryParse(value.ToString(), out var result)
            ? result
            : null;
}
