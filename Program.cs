using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Microsoft.Win32;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls("http://127.0.0.1:5117");

var app = builder.Build();
EventStore.Configure(app.Environment.ContentRootPath);
AgentPolicyStore.Configure(app.Environment.ContentRootPath);
IpBlockStore.Configure(app.Environment.ContentRootPath);

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/api/summary", async () =>
{
    var connections = await TelemetryService.GetConnectionsAsync();
    var processes = TelemetryService.GetProcesses(connections);
    var startupEntries = TelemetryService.GetStartupEntries();
    var defender = await TelemetryService.GetDefenderStatusAsync();
    var policy = AgentPolicyStore.Load();
    var alerts = DetectionEngine.BuildAlerts(connections, processes, startupEntries, defender, policy).ToList();
    EventStore.RecordAlerts(alerts);

    return Results.Ok(new SummaryDto(
        Environment.MachineName,
        RuntimeInformation.OSDescription,
        TelemetryService.IsAdministrator(),
        DateTimeOffset.Now,
        connections.Count,
        processes.Count,
        startupEntries.Count,
        defender,
        alerts.Count(a => a.Severity == "High"),
        alerts.Count(a => a.Severity == "Medium"),
        alerts.Count(a => a.Severity == "Low")));
});

app.MapGet("/api/connections", async () =>
{
    var connections = await TelemetryService.GetConnectionsAsync();
    return Results.Ok(connections.OrderByDescending(c => c.RiskScore).ThenBy(c => c.ProcessName));
});

app.MapGet("/api/processes", async () =>
{
    var connections = await TelemetryService.GetConnectionsAsync();
    var policy = AgentPolicyStore.Load();
    return Results.Ok(TelemetryService.GetProcesses(connections, policy).OrderByDescending(p => p.RiskScore).ThenByDescending(p => p.MemoryMb));
});

app.MapGet("/api/performance", async () =>
{
    var connections = await TelemetryService.GetConnectionsAsync();
    var policy = AgentPolicyStore.Load();
    var processes = TelemetryService.GetProcesses(connections, policy);
    var memory = ResourceMonitor.GetMemory();
    return Results.Ok(new PerformanceDto(
        DateTimeOffset.Now,
        memory,
        processes.Count,
        processes.Count(p => p.MemoryMb >= 500),
        processes.Count(p => p.CpuPercent >= 10),
        processes.OrderByDescending(p => p.MemoryMb).Take(20),
        processes.OrderByDescending(p => p.CpuPercent).Take(20)));
});

app.MapGet("/api/startup", () => Results.Ok(TelemetryService.GetStartupEntries()));

app.MapGet("/api/defender", async () => Results.Ok(await TelemetryService.GetDefenderStatusAsync()));

app.MapGet("/api/alerts", async () =>
{
    var connections = await TelemetryService.GetConnectionsAsync();
    var policy = AgentPolicyStore.Load();
    var processes = TelemetryService.GetProcesses(connections, policy);
    var startupEntries = TelemetryService.GetStartupEntries();
    var defender = await TelemetryService.GetDefenderStatusAsync();
    var freshAlerts = DetectionEngine.BuildAlerts(connections, processes, startupEntries, defender, policy).ToList();
    EventStore.RecordAlerts(freshAlerts);

    return Results.Ok(EventStore.GetRecentAlerts());
});

app.MapGet("/api/logs", () => Results.Ok(EventStore.GetRecentAlerts(500)));

app.MapGet("/api/policies", () =>
{
    var agentPolicy = AgentPolicyStore.Load();
    return Results.Ok(new PolicyReviewDto(
        agentPolicy.AuthorizedPaths.OrderBy(path => path),
        agentPolicy.BlockedPaths.OrderBy(path => path),
        IpBlockStore.Load().OrderByDescending(block => block.BlockedAt),
        PolicyCatalog.ActivePolicies));
});

app.MapPost("/api/actions/scan", async (ScanRequest request) =>
{
    var scanType = request.Type?.ToLowerInvariant() switch
    {
        "full" => "FullScan",
        "deep" => "FullScan",
        _ => "QuickScan"
    };
    var updateFirst = string.Equals(request.Type, "deep", StringComparison.OrdinalIgnoreCase);
    var result = await TelemetryService.StartDefenderScanAsync(scanType, updateFirst);
    var severity = result.ExitCode == 0 ? "Low" : "Medium";
    EventStore.RecordAction("Defender scan requested", severity, result.ExitCode == 0
        ? $"{scanType} was started in the background by Microsoft Defender."
        : result.Error);

    return Results.Ok(new ActionResultDto(result.ExitCode == 0, result.Output, result.Error));
});

app.MapGet("/api/agents", async () =>
{
    var connections = await TelemetryService.GetConnectionsAsync();
    var policy = AgentPolicyStore.Load();
    var agents = TelemetryService.GetProcesses(connections, policy)
        .Where(p => p.IsAgent)
        .OrderBy(p => p.NetworkAuthorized)
        .ThenByDescending(p => p.ConnectionCount)
        .ToList();

    return Results.Ok(new AgentViewDto(policy.AuthorizedPaths.OrderBy(p => p), policy.BlockedPaths.OrderBy(p => p), agents));
});

app.MapPost("/api/actions/authorize-agent", async (AgentPolicyRequest request) =>
{
    if (string.IsNullOrWhiteSpace(request.Path))
    {
        return Results.BadRequest(new ActionResultDto(false, "", "Agent path is required."));
    }

    var policy = AgentPolicyStore.Authorize(request.Path);
    await FirewallService.RemoveProgramBlockAsync(request.Path);
    EventStore.RecordAction("Agent authorized", "Medium", request.Path);
    return Results.Ok(new ActionResultDto(true, $"Authorized {request.Path}", ""));
});

app.MapPost("/api/actions/block-agent", async (AgentPolicyRequest request) =>
{
    if (string.IsNullOrWhiteSpace(request.Path))
    {
        return Results.BadRequest(new ActionResultDto(false, "", "Agent path is required."));
    }

    AgentPolicyStore.Block(request.Path);
    var result = await FirewallService.BlockProgramAsync(request.Path);
    EventStore.RecordAction("Agent blocked", result.ExitCode == 0 ? "High" : "Medium",
        result.ExitCode == 0 ? request.Path : result.Error);
    return Results.Ok(new ActionResultDto(result.ExitCode == 0, result.Output, result.Error));
});

app.MapPost("/api/actions/unblock-agent", async (AgentPolicyRequest request) =>
{
    if (string.IsNullOrWhiteSpace(request.Path))
    {
        return Results.BadRequest(new ActionResultDto(false, "", "Agent path is required."));
    }

    AgentPolicyStore.Unblock(request.Path);
    var result = await FirewallService.RemoveProgramBlockAsync(request.Path);
    EventStore.RecordAction("Agent block restored", result.ExitCode == 0 ? "Medium" : "High",
        result.ExitCode == 0 ? $"Removed RoamSentinel outbound block for {request.Path}." : result.Error);
    return Results.Ok(new ActionResultDto(result.ExitCode == 0, result.Output, result.Error));
});

app.MapPost("/api/actions/enforce-agent-policy", async () =>
{
    var connections = await TelemetryService.GetConnectionsAsync();
    var policy = AgentPolicyStore.Load();
    var agents = TelemetryService.GetProcesses(connections, policy)
        .Where(p => p.IsAgent && !p.NetworkAuthorized && !string.IsNullOrWhiteSpace(p.Path))
        .GroupBy(p => p.Path, StringComparer.OrdinalIgnoreCase)
        .Select(g => g.Key)
        .ToList();

    var blocked = new List<string>();
    var errors = new List<string>();
    foreach (var path in agents)
    {
        AgentPolicyStore.Block(path);
        var result = await FirewallService.BlockProgramAsync(path);
        if (result.ExitCode == 0)
        {
            blocked.Add(path);
        }
        else
        {
            errors.Add($"{path}: {result.Error}");
        }
    }

    EventStore.RecordAction("Agent policy enforced", blocked.Count > 0 ? "High" : "Low", $"{blocked.Count} unapproved agent executable(s) blocked.");
    return Results.Ok(new ActionResultDto(errors.Count == 0, string.Join(Environment.NewLine, blocked), string.Join(Environment.NewLine, errors)));
});

app.MapPost("/api/logs/purge", () =>
{
    var count = EventStore.Purge();
    EventStore.RecordAction("Logs purged after review", "Low", $"{count} logged event(s) were cleared.");
    return Results.Ok(new ActionResultDto(true, $"Purged {count} logged event(s).", ""));
});

app.MapPost("/api/actions/block-ip", async (BlockIpRequest request) =>
{
    if (!IPAddress.TryParse(request.IpAddress, out var ip))
    {
        return Results.BadRequest(new ActionResultDto(false, "", "Enter a valid IPv4 or IPv6 address."));
    }

    if (IPAddress.IsLoopback(ip))
    {
        return Results.BadRequest(new ActionResultDto(false, "", "Loopback addresses are not blocked."));
    }

    var stamp = DateTimeOffset.Now.ToString("yyyyMMddHHmmss");
    var displayName = $"RoamSentinel Block {ip} {stamp}";
    var escapedName = TextEscaper.PowerShellSingleQuoted(displayName);
    var escapedIp = TextEscaper.PowerShellSingleQuoted(ip.ToString());
    var command = $"""
        New-NetFirewallRule -DisplayName '{escapedName} Outbound' -Direction Outbound -RemoteAddress '{escapedIp}' -Action Block -Profile Any -ErrorAction Stop;
        New-NetFirewallRule -DisplayName '{escapedName} Inbound' -Direction Inbound -RemoteAddress '{escapedIp}' -Action Block -Profile Any -ErrorAction Stop
        """;

    var result = await TelemetryService.RunPowerShellAsync(command, TimeSpan.FromSeconds(25));
    EventStore.RecordAction("Firewall block requested", result.ExitCode == 0 ? "Medium" : "High",
        result.ExitCode == 0 ? $"Windows Firewall block rules were added for {ip}." : result.Error);
    if (result.ExitCode == 0)
    {
        IpBlockStore.Record(new IpBlockDto(ip.ToString(), displayName, DateTimeOffset.Now));
    }

    return Results.Ok(new ActionResultDto(result.ExitCode == 0, result.Output, result.Error));
});

app.MapPost("/api/actions/unblock-ip", async (UnblockIpRequest request) =>
{
    if (!IPAddress.TryParse(request.IpAddress, out var ip))
    {
        return Results.BadRequest(new ActionResultDto(false, "", "Enter a valid blocked IP address."));
    }

    var block = IpBlockStore.Find(ip.ToString());
    if (block is null)
    {
        return Results.NotFound(new ActionResultDto(false, "", "RoamSentinel has no stored block for that IP."));
    }

    var result = await FirewallService.RemoveIpBlockAsync(block);
    if (result.ExitCode == 0)
    {
        IpBlockStore.Remove(block.IpAddress);
    }

    EventStore.RecordAction("IP block restored", result.ExitCode == 0 ? "Medium" : "High",
        result.ExitCode == 0 ? $"Removed RoamSentinel Windows Firewall rules for {block.IpAddress}." : result.Error);
    return Results.Ok(new ActionResultDto(result.ExitCode == 0, result.Output, result.Error));
});

app.MapPost("/api/actions/kill-process", (KillProcessRequest request) =>
{
    if (request.ProcessId <= 0 || request.ProcessId == Environment.ProcessId)
    {
        return Results.BadRequest(new ActionResultDto(false, "", "That process cannot be stopped from RoamSentinel."));
    }

    try
    {
        var process = Process.GetProcessById(request.ProcessId);
        var name = process.ProcessName;
        process.Kill(entireProcessTree: true);
        EventStore.RecordAction("Process stopped", "High", $"{name} ({request.ProcessId}) was stopped by user action.");
        return Results.Ok(new ActionResultDto(true, $"{name} ({request.ProcessId}) stopped.", ""));
    }
    catch (Exception ex)
    {
        return Results.Ok(new ActionResultDto(false, "", ex.Message));
    }
});

app.MapFallbackToFile("index.html");

app.Run();

static class TelemetryService
{
    private static readonly HashSet<string> ScriptableProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "cmd"
    };

    public static async Task<List<ConnectionDto>> GetConnectionsAsync()
    {
        var command = """
            $tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object @{n='Protocol';e={'TCP'}},LocalAddress,LocalPort,RemoteAddress,RemotePort,@{n='State';e={$_.State.ToString()}},OwningProcess;
            $udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object @{n='Protocol';e={'UDP'}},LocalAddress,LocalPort,@{n='RemoteAddress';e={''}},@{n='RemotePort';e={0}},@{n='State';e={'Listening'}},OwningProcess;
            @(@($tcp) + @($udp)) | ConvertTo-Json -Depth 4
            """;

        var result = await RunPowerShellAsync(command, TimeSpan.FromSeconds(12));
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.Output))
        {
            return [];
        }

        try
        {
            using var doc = JsonDocument.Parse(result.Output);
            return EnumerateObjects(doc.RootElement)
                .Select(ReadConnection)
                .Where(c => c is not null)
                .Cast<ConnectionDto>()
                .ToList();
        }
        catch
        {
            return [];
        }
    }

    public static List<ProcessDto> GetProcesses(IEnumerable<ConnectionDto> connections, AgentPolicy? policy = null)
    {
        var connectionCounts = connections
            .GroupBy(c => c.ProcessId)
            .ToDictionary(g => g.Key, g => g.Count());

        policy ??= AgentPolicyStore.Load();
        return Process.GetProcesses()
            .Select(process => ReadProcess(process, connectionCounts.GetValueOrDefault(process.Id), policy))
            .Where(p => p is not null)
            .Cast<ProcessDto>()
            .ToList();
    }

    public static List<StartupEntryDto> GetStartupEntries()
    {
        var entries = new List<StartupEntryDto>();
        ReadRunKey(entries, Registry.CurrentUser, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\Run");
        ReadRunKey(entries, Registry.LocalMachine, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\Run");
        ReadAutoServices(entries);
        ReadScheduledTasks(entries);

        AddStartupFolder(entries, Environment.GetFolderPath(Environment.SpecialFolder.Startup), "Current user startup folder");
        AddStartupFolder(entries, Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "All users startup folder");
        return entries.OrderBy(e => e.Source).ThenBy(e => e.Name).ToList();
    }

    public static async Task<DefenderStatusDto> GetDefenderStatusAsync()
    {
        var command = """
            Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntispywareEnabled,NISEnabled,QuickScanAge,FullScanAge,AntivirusSignatureLastUpdated,AntivirusSignatureVersion | ConvertTo-Json -Depth 3
            """;
        var result = await RunPowerShellAsync(command, TimeSpan.FromSeconds(10));

        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.Output))
        {
            return new DefenderStatusDto(false, false, false, false, null, null, null, "", "Microsoft Defender status is unavailable. The service or PowerShell module may be disabled.");
        }

        try
        {
            using var doc = JsonDocument.Parse(result.Output);
            var root = doc.RootElement;
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
            return new DefenderStatusDto(false, false, false, false, null, null, null, "", ex.Message);
        }
    }

    public static async Task<CommandResult> RunPowerShellAsync(string command, TimeSpan timeout)
    {
        var encodedCommand = Convert.ToBase64String(Encoding.Unicode.GetBytes(command));
        var startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -EncodedCommand {encodedCommand}",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = new Process { StartInfo = startInfo };
        try
        {
            process.Start();
            var outputTask = process.StandardOutput.ReadToEndAsync();
            var errorTask = process.StandardError.ReadToEndAsync();
            var waitTask = process.WaitForExitAsync();
            var completed = await Task.WhenAny(waitTask, Task.Delay(timeout));
            if (completed != waitTask)
            {
                TryKill(process);
                return new CommandResult(-1, await outputTask, "Command timed out.");
            }

            return new CommandResult(process.ExitCode, (await outputTask).Trim(), (await errorTask).Trim());
        }
        catch (Exception ex)
        {
            return new CommandResult(-1, "", ex.Message);
        }
    }

    public static async Task<CommandResult> StartDefenderScanAsync(string scanType, bool updateFirst)
    {
        var body = updateFirst
            ? $"Update-MpSignature; Start-MpScan -ScanType {scanType}"
            : $"Start-MpScan -ScanType {scanType}";
        var encodedBody = Convert.ToBase64String(Encoding.Unicode.GetBytes(body));
        var command = $"""
            Start-Process powershell.exe -WindowStyle Hidden -ArgumentList '-NoProfile -ExecutionPolicy Bypass -EncodedCommand {encodedBody}'
            """;

        return await RunPowerShellAsync(command, TimeSpan.FromSeconds(8));
    }

    public static bool IsAdministrator()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static ConnectionDto? ReadConnection(JsonElement element)
    {
        var processId = GetInt(element, "OwningProcess");
        var processName = TryGetProcessName(processId);
        var processPath = TryGetProcessPath(processId);
        var localAddress = GetString(element, "LocalAddress");
        var remoteAddress = GetString(element, "RemoteAddress");
        var remotePort = GetInt(element, "RemotePort");
        var state = GetString(element, "State");
        var protocol = GetString(element, "Protocol");
        var localPort = GetInt(element, "LocalPort");
        var risk = ScoreConnection(remoteAddress, remotePort, state, processName, processPath);

        return new ConnectionDto(
            protocol,
            localAddress,
            localPort,
            remoteAddress,
            remotePort,
            state,
            processId,
            processName,
            processPath,
            risk.Score,
            risk.Reason);
    }

    private static ProcessDto? ReadProcess(Process process, int connectionCount, AgentPolicy policy)
    {
        try
        {
            var path = TryGetProcessPath(process.Id);
            var name = process.ProcessName;
            var isAgent = IsAgentProcess(name, path);
            var networkAuthorized = !isAgent || policy.AuthorizedPaths.Contains(path);
            var risk = ScoreProcess(name, path, connectionCount, isAgent, networkAuthorized);
            var cpuPercent = ResourceMonitor.GetProcessCpuPercent(process);
            return new ProcessDto(
                process.Id,
                name,
                path,
                Math.Round(process.WorkingSet64 / 1024d / 1024d, 1),
                Math.Round(process.PrivateMemorySize64 / 1024d / 1024d, 1),
                cpuPercent,
                TryGetHandleCount(process),
                TryGetThreadCount(process),
                connectionCount,
                process.StartTimeSafe(),
                risk.Score,
                risk.Reason,
                isAgent,
                networkAuthorized);
        }
        catch
        {
            return null;
        }
    }

    private static void ReadRunKey(List<StartupEntryDto> entries, RegistryKey hive, string hiveName, string path)
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
                var value = key.GetValue(name)?.ToString() ?? "";
                entries.Add(new StartupEntryDto(name, value, $"{hiveName}\\{path}", ScoreStartup(value)));
            }
        }
        catch
        {
        }
    }

    private static void AddStartupFolder(List<StartupEntryDto> entries, string folder, string source)
    {
        if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder))
        {
            return;
        }

        foreach (var file in Directory.EnumerateFiles(folder))
        {
            entries.Add(new StartupEntryDto(Path.GetFileName(file), file, source, ScoreStartup(file)));
        }
    }

    private static void ReadAutoServices(List<StartupEntryDto> entries)
    {
        try
        {
            using var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (services is null)
            {
                return;
            }

            foreach (var serviceName in services.GetSubKeyNames())
            {
                using var service = services.OpenSubKey(serviceName);
                if (service is null || Convert.ToInt32(service.GetValue("Start", 99)) != 2)
                {
                    continue;
                }

                var imagePath = service.GetValue("ImagePath")?.ToString() ?? "";
                var score = ScoreStartup(imagePath);
                if (score >= 40)
                {
                    entries.Add(new StartupEntryDto(serviceName, imagePath, "Auto-start service", score));
                }
            }
        }
        catch
        {
        }
    }

    private static void ReadScheduledTasks(List<StartupEntryDto> entries)
    {
        var taskRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
        if (!Directory.Exists(taskRoot))
        {
            return;
        }

        var options = new EnumerationOptions
        {
            IgnoreInaccessible = true,
            RecurseSubdirectories = true
        };

        foreach (var taskFile in Directory.EnumerateFiles(taskRoot, "*", options))
        {
            try
            {
                var doc = XDocument.Load(taskFile);
                var command = string.Join(" ", doc.Descendants().Where(e => e.Name.LocalName is "Command" or "Arguments").Select(e => e.Value.Trim()));
                var score = ScoreStartup(command);
                if (score >= 40)
                {
                    entries.Add(new StartupEntryDto(Path.GetRelativePath(taskRoot, taskFile), command, "Scheduled task", score));
                }
            }
            catch
            {
            }
        }
    }

    private static Risk ScoreConnection(string remoteAddress, int remotePort, string state, string processName, string processPath)
    {
        if (string.IsNullOrWhiteSpace(remoteAddress) || remoteAddress is "0.0.0.0" or "::" or "*")
        {
            return new Risk(0, "");
        }

        var score = 0;
        var reasons = new List<string>();
        var isPublic = IsPublicAddress(remoteAddress);
        var suspiciousPorts = new HashSet<int> { 23, 2323, 4444, 5555, 6667, 1337, 31337, 3389, 5900 };

        if (isPublic && string.Equals(state, "Established", StringComparison.OrdinalIgnoreCase))
        {
            score += 20;
            reasons.Add("public established connection");
        }

        if (suspiciousPorts.Contains(remotePort))
        {
            score += 35;
            reasons.Add($"sensitive remote port {remotePort}");
        }

        if (isPublic && ScriptableProcessNames.Contains(processName))
        {
            score += 35;
            reasons.Add("script-capable process is online");
        }

        if (IsTempOrUserWritablePath(processPath))
        {
            score += 25;
            reasons.Add("process runs from a user-writable path");
        }

        return new Risk(Math.Min(score, 100), string.Join(", ", reasons));
    }

    private static Risk ScoreProcess(string processName, string processPath, int connectionCount, bool isAgent, bool networkAuthorized)
    {
        var score = 0;
        var reasons = new List<string>();

        if (ScriptableProcessNames.Contains(processName) && connectionCount > 0)
        {
            score += 35;
            reasons.Add("script-capable process has network activity");
        }

        if (connectionCount >= 25)
        {
            score += 25;
            reasons.Add("many network connections");
        }

        if (IsTempOrUserWritablePath(processPath))
        {
            score += 25;
            reasons.Add("runs from a user-writable path");
        }

        if (isAgent && connectionCount > 0 && !networkAuthorized)
        {
            score += 80;
            reasons.Add("AI/dev agent has network activity without authorization");
        }

        return new Risk(Math.Min(score, 100), string.Join(", ", reasons));
    }

    private static bool IsAgentProcess(string name, string path)
    {
        var value = $"{name} {path}".ToLowerInvariant();
        return value.Contains("codex")
            || value.Contains("claude")
            || value.Contains("anthropic")
            || value.Contains("cursor")
            || value.Contains("windsurf")
            || value.Contains("aider")
            || value.Contains("roo-code")
            || value.Contains("cline");
    }

    private static int ScoreStartup(string command)
    {
        var lower = command.ToLowerInvariant();
        var score = 0;
        if (lower.Contains(@"\appdata\") || lower.Contains(@"\temp\"))
        {
            score += 40;
        }

        if (lower.Contains("powershell") || lower.Contains("wscript") || lower.Contains("mshta") || lower.Contains("rundll32"))
        {
            score += 35;
        }

        return Math.Min(score, 100);
    }

    private static bool IsPublicAddress(string value)
    {
        if (!IPAddress.TryParse(value, out var ip))
        {
            return true;
        }

        if (IPAddress.IsLoopback(ip))
        {
            return false;
        }

        var bytes = ip.GetAddressBytes();
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return !(bytes[0] == 10
                || bytes[0] == 127
                || bytes[0] == 169 && bytes[1] == 254
                || bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31
                || bytes[0] == 192 && bytes[1] == 168);
        }

        return !ip.IsIPv6LinkLocal && !ip.IsIPv6SiteLocal && !ip.IsIPv6Multicast;
    }

    private static bool IsTempOrUserWritablePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var lower = path.ToLowerInvariant();
        return lower.Contains(@"\appdata\local\temp\")
            || lower.Contains(@"\appdata\roaming\")
            || lower.Contains(@"\downloads\")
            || lower.Contains(@"\users\public\");
    }

    private static IEnumerable<JsonElement> EnumerateObjects(JsonElement root)
    {
        if (root.ValueKind == JsonValueKind.Array)
        {
            foreach (var element in root.EnumerateArray())
            {
                if (element.ValueKind == JsonValueKind.Object)
                {
                    yield return element;
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
            return processId > 0 ? Process.GetProcessById(processId).ProcessName : "System";
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
            return processId > 0 ? Process.GetProcessById(processId).MainModule?.FileName ?? "" : "";
        }
        catch
        {
            return "";
        }
    }

    private static int TryGetHandleCount(Process process)
    {
        try
        {
            return process.HandleCount;
        }
        catch
        {
            return 0;
        }
    }

    private static int TryGetThreadCount(Process process)
    {
        try
        {
            return process.Threads.Count;
        }
        catch
        {
            return 0;
        }
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch
        {
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

    private static int GetInt(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var value))
        {
            return 0;
        }

        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number))
        {
            return number;
        }

        return int.TryParse(value.ToString(), out var parsed) ? parsed : 0;
    }

    private static int? GetNullableInt(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var value) || value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        return int.TryParse(value.ToString(), out var parsed) ? parsed : null;
    }

    private static bool GetBool(JsonElement element, string property)
    {
        return element.TryGetProperty(property, out var value) && value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.String => bool.TryParse(value.GetString(), out var parsed) && parsed,
            _ => false
        };
    }

    private static DateTimeOffset? GetNullableDate(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var value))
        {
            return null;
        }

        return DateTimeOffset.TryParse(value.ToString(), out var parsed) ? parsed : null;
    }
}

static class DetectionEngine
{
    public static IEnumerable<AlertDto> BuildAlerts(
        IEnumerable<ConnectionDto> connections,
        IEnumerable<ProcessDto> processes,
        IEnumerable<StartupEntryDto> startupEntries,
        DefenderStatusDto defender,
        AgentPolicy policy)
    {
        foreach (var connection in connections.Where(c => c.RiskScore >= 55).Take(30))
        {
            yield return Alert("Network", Severity(connection.RiskScore), $"{connection.ProcessName} connection", $"{connection.ProcessName} ({connection.ProcessId}) -> {connection.RemoteAddress}:{connection.RemotePort}. {connection.RiskReason}");
        }

        foreach (var process in processes.Where(p => p.RiskScore >= 50).Take(30))
        {
            yield return Alert("Process", Severity(process.RiskScore), $"{process.Name} process risk", $"{process.Name} ({process.ProcessId}) has {process.ConnectionCount} connection(s). {process.RiskReason}");
        }

        foreach (var entry in startupEntries.Where(s => s.RiskScore >= 40).Take(30))
        {
            yield return Alert("Persistence", Severity(entry.RiskScore), $"Startup entry: {entry.Name}", $"{entry.Source}: {entry.Command}");
        }

        if (!defender.RealTimeProtectionEnabled || !defender.AntivirusEnabled)
        {
            yield return Alert("Defender", "High", "Microsoft Defender protection issue", defender.Message.Length > 0 ? defender.Message : "Real-time or antivirus protection is disabled.");
        }

        if (defender.QuickScanAge is > 7)
        {
            yield return Alert("Scan", "Medium", "Quick scan is stale", $"Last quick scan age: {defender.QuickScanAge} day(s).");
        }

        foreach (var agent in processes.Where(p => p.IsAgent && p.ConnectionCount > 0 && !p.NetworkAuthorized).Take(20))
        {
            yield return Alert("Agent Access", "High", $"Unauthorized agent network activity: {agent.Name}", $"{agent.Name} ({agent.ProcessId}) has {agent.ConnectionCount} connection(s). Authorize or block this executable path: {agent.Path}");
        }

        foreach (var blockedPath in policy.BlockedPaths)
        {
            yield return Alert("Agent Access", "Low", "Blocked agent policy active", blockedPath);
        }
    }

    private static AlertDto Alert(string category, string severity, string title, string detail)
    {
        var id = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes($"{category}|{severity}|{title}|{detail}")))[..16];
        return new AlertDto(id, DateTimeOffset.Now, category, severity, title, detail);
    }

    private static string Severity(int score) => score >= 70 ? "High" : score >= 45 ? "Medium" : "Low";
}

static class EventStore
{
    private static readonly ConcurrentDictionary<string, AlertDto> Alerts = new();
    private static readonly Lock Gate = new();
    private static string LogFile = "";

    public static void Configure(string contentRoot)
    {
        var dataDir = Path.Combine(contentRoot, "data");
        Directory.CreateDirectory(dataDir);
        LogFile = Path.Combine(dataDir, "events.jsonl");

        if (!File.Exists(LogFile))
        {
            return;
        }

        foreach (var line in File.ReadLines(LogFile))
        {
            try
            {
                var alert = JsonSerializer.Deserialize<AlertDto>(line);
                if (alert is not null)
                {
                    Alerts[alert.Id] = alert;
                }
            }
            catch
            {
            }
        }
    }

    public static void RecordAlerts(IEnumerable<AlertDto> alerts)
    {
        foreach (var alert in alerts)
        {
            if (Alerts.TryAdd(alert.Id, alert))
            {
                Append(alert);
            }
        }
    }

    public static void RecordAction(string title, string severity, string detail)
    {
        var id = Guid.NewGuid().ToString("N");
        var alert = new AlertDto(id, DateTimeOffset.Now, "Action", severity, title, detail);
        Alerts[id] = alert;
        Append(alert);
    }

    public static IEnumerable<AlertDto> GetRecentAlerts(int limit = 200) =>
        Alerts.Values.OrderByDescending(a => a.Timestamp).Take(limit);

    public static int Purge()
    {
        lock (Gate)
        {
            var count = Alerts.Count;
            Alerts.Clear();
            if (!string.IsNullOrWhiteSpace(LogFile))
            {
                File.WriteAllText(LogFile, "");
            }

            return count;
        }
    }

    private static void Append(AlertDto alert)
    {
        if (string.IsNullOrWhiteSpace(LogFile))
        {
            return;
        }

        lock (Gate)
        {
            File.AppendAllText(LogFile, JsonSerializer.Serialize(alert) + Environment.NewLine);
        }
    }
}

static class AgentPolicyStore
{
    private static readonly Lock Gate = new();
    private static string PolicyFile = "";

    public static void Configure(string contentRoot)
    {
        var dataDir = Path.Combine(contentRoot, "data");
        Directory.CreateDirectory(dataDir);
        PolicyFile = Path.Combine(dataDir, "agent-policy.json");
        if (!File.Exists(PolicyFile))
        {
            Save(new AgentPolicy([], []));
        }
    }

    public static AgentPolicy Load()
    {
        lock (Gate)
        {
            return LoadNoLock();
        }
    }

    public static AgentPolicy Authorize(string path)
    {
        lock (Gate)
        {
            var policy = LoadNoLock();
            policy.AuthorizedPaths.Add(path);
            policy.BlockedPaths.Remove(path);
            Save(policy);
            return policy;
        }
    }

    public static AgentPolicy Block(string path)
    {
        lock (Gate)
        {
            var policy = LoadNoLock();
            policy.BlockedPaths.Add(path);
            policy.AuthorizedPaths.Remove(path);
            Save(policy);
            return policy;
        }
    }

    public static AgentPolicy Unblock(string path)
    {
        lock (Gate)
        {
            var policy = LoadNoLock();
            policy.BlockedPaths.Remove(path);
            Save(policy);
            return policy;
        }
    }

    private static AgentPolicy LoadNoLock()
    {
        try
        {
            var policy = JsonSerializer.Deserialize<AgentPolicy>(File.ReadAllText(PolicyFile));
            return Normalize(policy ?? new AgentPolicy([], []));
        }
        catch
        {
            return new AgentPolicy([], []);
        }
    }

    private static void Save(AgentPolicy policy)
    {
        File.WriteAllText(PolicyFile, JsonSerializer.Serialize(Normalize(policy), new JsonSerializerOptions { WriteIndented = true }));
    }

    private static AgentPolicy Normalize(AgentPolicy policy) =>
        new(policy.AuthorizedPaths, policy.BlockedPaths);
}

static class FirewallService
{
    public static Task<CommandResult> BlockProgramAsync(string path)
    {
        var escapedPath = TextEscaper.PowerShellSingleQuoted(path);
        var command = $"""
            $program = '{escapedPath}';
            $name = 'RoamSentinel Agent Block ' + ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($program))).Substring(0, 24);
            Get-NetFirewallRule -DisplayName ('PcGuardian Agent Block ' + ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($program))).Substring(0, 24) + '*') -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue;
            Get-NetFirewallRule -DisplayName "$name*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue;
            New-NetFirewallRule -DisplayName "$name Outbound" -Direction Outbound -Program $program -Action Block -Profile Any -ErrorAction Stop
            """;

        return TelemetryService.RunPowerShellAsync(command, TimeSpan.FromSeconds(25));
    }

    public static Task<CommandResult> RemoveProgramBlockAsync(string path)
    {
        var escapedPath = TextEscaper.PowerShellSingleQuoted(path);
        var command = $"""
            $program = '{escapedPath}';
            $name = 'RoamSentinel Agent Block ' + ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($program))).Substring(0, 24);
            Get-NetFirewallRule -DisplayName ('PcGuardian Agent Block ' + ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($program))).Substring(0, 24) + '*') -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue;
            Get-NetFirewallRule -DisplayName "$name*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
            """;

        return TelemetryService.RunPowerShellAsync(command, TimeSpan.FromSeconds(20));
    }

    public static Task<CommandResult> RemoveIpBlockAsync(IpBlockDto block)
    {
        var escapedName = TextEscaper.PowerShellSingleQuoted(block.DisplayName);
        var command = $"""
            Get-NetFirewallRule -DisplayName '{escapedName} Outbound' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop;
            Get-NetFirewallRule -DisplayName '{escapedName} Inbound' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
            """;

        return TelemetryService.RunPowerShellAsync(command, TimeSpan.FromSeconds(20));
    }
}

static class IpBlockStore
{
    private static readonly Lock Gate = new();
    private static string StoreFile = "";

    public static void Configure(string contentRoot)
    {
        var dataDir = Path.Combine(contentRoot, "data");
        Directory.CreateDirectory(dataDir);
        StoreFile = Path.Combine(dataDir, "ip-blocks.json");
        if (!File.Exists(StoreFile))
        {
            SaveNoLock([]);
        }
    }

    public static IReadOnlyList<IpBlockDto> Load()
    {
        lock (Gate)
        {
            return LoadNoLock();
        }
    }

    public static IpBlockDto? Find(string ipAddress)
    {
        lock (Gate)
        {
            return LoadNoLock().FirstOrDefault(block => string.Equals(block.IpAddress, ipAddress, StringComparison.OrdinalIgnoreCase));
        }
    }

    public static void Record(IpBlockDto block)
    {
        lock (Gate)
        {
            var blocks = LoadNoLock()
                .Where(existing => !string.Equals(existing.IpAddress, block.IpAddress, StringComparison.OrdinalIgnoreCase))
                .Append(block)
                .ToList();
            SaveNoLock(blocks);
        }
    }

    public static void Remove(string ipAddress)
    {
        lock (Gate)
        {
            SaveNoLock(LoadNoLock()
                .Where(block => !string.Equals(block.IpAddress, ipAddress, StringComparison.OrdinalIgnoreCase))
                .ToList());
        }
    }

    private static List<IpBlockDto> LoadNoLock()
    {
        try
        {
            return JsonSerializer.Deserialize<List<IpBlockDto>>(File.ReadAllText(StoreFile)) ?? [];
        }
        catch
        {
            return [];
        }
    }

    private static void SaveNoLock(IEnumerable<IpBlockDto> blocks)
    {
        File.WriteAllText(StoreFile, JsonSerializer.Serialize(blocks, new JsonSerializerOptions { WriteIndented = true }));
    }
}

static class PolicyCatalog
{
    public static readonly PolicyRuleDto[] ActivePolicies =
    [
        new("Local dashboard", "RoamSentinel binds to 127.0.0.1:5117 only."),
        new("Agent exception", "AI/dev agent executable paths are unapproved until authorized."),
        new("Agent block", "Blocked agent paths receive RoamSentinel outbound Windows Firewall rules."),
        new("IP block", "Blocked remote IPs receive inbound and outbound Windows Firewall rules."),
        new("Log review", "Alert and action logs persist until the review purge action is used."),
        new("Persistence scan", "Unreadable protected scheduled-task folders are skipped and readable task commands are checked.")
    ];
}

static class ResourceMonitor
{
    private static readonly ConcurrentDictionary<int, CpuSample> CpuSamples = new();

    public static MemoryDto GetMemory()
    {
        var status = new MemoryStatusEx();
        status.dwLength = (uint)Marshal.SizeOf<MemoryStatusEx>();
        if (!GlobalMemoryStatusEx(ref status))
        {
            return new MemoryDto(0, 0, 0, 0);
        }

        var totalGb = Math.Round(status.ullTotalPhys / 1024d / 1024d / 1024d, 2);
        var availableGb = Math.Round(status.ullAvailPhys / 1024d / 1024d / 1024d, 2);
        var usedGb = Math.Round(totalGb - availableGb, 2);
        return new MemoryDto(totalGb, usedGb, availableGb, status.dwMemoryLoad);
    }

    public static double GetProcessCpuPercent(Process process)
    {
        try
        {
            var now = DateTimeOffset.UtcNow;
            var total = process.TotalProcessorTime;
            if (!CpuSamples.TryGetValue(process.Id, out var previous))
            {
                CpuSamples[process.Id] = new CpuSample(total, now);
                return 0;
            }

            CpuSamples[process.Id] = new CpuSample(total, now);

            var elapsedMs = (now - previous.Timestamp).TotalMilliseconds;
            if (elapsedMs <= 0)
            {
                return 0;
            }

            var cpuMs = (total - previous.TotalProcessorTime).TotalMilliseconds;
            var percent = cpuMs / elapsedMs / Environment.ProcessorCount * 100d;
            if (double.IsNaN(percent) || double.IsInfinity(percent) || percent < 0)
            {
                return 0;
            }

            return Math.Round(Math.Min(percent, 100), 1);
        }
        catch
        {
            return 0;
        }
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

static class TextEscaper
{
    public static string PowerShellSingleQuoted(string value) => value.Replace("'", "''");
}

static class ProcessExtensions
{
    public static DateTimeOffset? StartTimeSafe(this Process process)
    {
        try
        {
            return process.StartTime;
        }
        catch
        {
            return null;
        }
    }
}

record Risk(int Score, string Reason);
record CpuSample(TimeSpan TotalProcessorTime, DateTimeOffset Timestamp);
record CommandResult(int ExitCode, string Output, string Error);
record SummaryDto(string MachineName, string Os, bool IsAdministrator, DateTimeOffset GeneratedAt, int ConnectionCount, int ProcessCount, int StartupEntryCount, DefenderStatusDto Defender, int HighAlerts, int MediumAlerts, int LowAlerts);
record ConnectionDto(string Protocol, string LocalAddress, int LocalPort, string RemoteAddress, int RemotePort, string State, int ProcessId, string ProcessName, string ProcessPath, int RiskScore, string RiskReason);
record ProcessDto(int ProcessId, string Name, string Path, double MemoryMb, double PrivateMemoryMb, double CpuPercent, int HandleCount, int ThreadCount, int ConnectionCount, DateTimeOffset? StartedAt, int RiskScore, string RiskReason, bool IsAgent, bool NetworkAuthorized);
record MemoryDto(double TotalGb, double UsedGb, double AvailableGb, uint UsedPercent);
record PerformanceDto(DateTimeOffset GeneratedAt, MemoryDto Memory, int ProcessCount, int HeavyMemoryProcessCount, int HeavyCpuProcessCount, IEnumerable<ProcessDto> TopMemoryProcesses, IEnumerable<ProcessDto> TopCpuProcesses);
record StartupEntryDto(string Name, string Command, string Source, int RiskScore);
record DefenderStatusDto(bool ServiceEnabled, bool AntivirusEnabled, bool RealTimeProtectionEnabled, bool NetworkInspectionEnabled, int? QuickScanAge, int? FullScanAge, DateTimeOffset? SignatureLastUpdated, string SignatureVersion, string Message);
record AlertDto(string Id, DateTimeOffset Timestamp, string Category, string Severity, string Title, string Detail);
record IpBlockDto(string IpAddress, string DisplayName, DateTimeOffset BlockedAt);
record PolicyRuleDto(string Name, string Detail);
record PolicyReviewDto(IEnumerable<string> AuthorizedAgentPaths, IEnumerable<string> BlockedAgentPaths, IEnumerable<IpBlockDto> BlockedIps, IEnumerable<PolicyRuleDto> ActivePolicies);
record ActionResultDto(bool Ok, string Output, string Error);
record ScanRequest(string Type);
record BlockIpRequest(string IpAddress);
record UnblockIpRequest(string IpAddress);
record KillProcessRequest(int ProcessId);
record AgentPolicyRequest(string Path);
record AgentViewDto(IEnumerable<string> AuthorizedPaths, IEnumerable<string> BlockedPaths, IEnumerable<ProcessDto> RunningAgents);
record AgentPolicy(HashSet<string> AuthorizedPaths, HashSet<string> BlockedPaths)
{
    public AgentPolicy() : this(new HashSet<string>(StringComparer.OrdinalIgnoreCase), new HashSet<string>(StringComparer.OrdinalIgnoreCase))
    {
    }

    public AgentPolicy(IEnumerable<string> authorizedPaths, IEnumerable<string> blockedPaths)
        : this(new HashSet<string>(authorizedPaths.Where(p => !string.IsNullOrWhiteSpace(p)), StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(blockedPaths.Where(p => !string.IsNullOrWhiteSpace(p)), StringComparer.OrdinalIgnoreCase))
    {
    }
}
