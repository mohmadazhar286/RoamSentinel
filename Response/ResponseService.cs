using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using RoamSentinel.Config;
using RoamSentinel.Core;

namespace RoamSentinel.Response;

public sealed class ResponseService(
    IPowerShellRunner powerShell,
    IIpBlockRepository ipBlocks,
    IAgentEgressRuleRepository agentEgressRules,
    IResponseActionRepository responseActions,
    IDisabledStartupRepository disabledStartup,
    IEventRepository events,
    IEventLogService eventLog,
    IPrivilegeService privileges,
    ResponseOptions options) : IResponseService
{
    private const string Operator = "authorized-local-operator";

    public async Task<ActionResultDto> StartDefenderScanAsync(
        string requestedType,
        CancellationToken cancellationToken = default)
    {
        var requestedAt = DateTimeOffset.UtcNow;
        if (options.DryRun)
        {
            return DryRun("defender.scan", requestedType, requestedAt);
        }
        var elevation = RequireAdministrator(
            "defender.scan",
            requestedType,
            requestedAt);
        if (elevation is not null)
        {
            return elevation;
        }

        var scanType = requestedType.ToLowerInvariant() switch
        {
            "full" => "FullScan",
            "deep" => "FullScan",
            _ => "QuickScan"
        };
        var updateFirst = string.Equals(
            requestedType,
            "deep",
            StringComparison.OrdinalIgnoreCase);
        var body = updateFirst
            ? $"Update-MpSignature; Start-MpScan -ScanType {scanType}"
            : $"Start-MpScan -ScanType {scanType}";
        var encodedBody = Convert.ToBase64String(Encoding.Unicode.GetBytes(body));
        var command = $"""
            Start-Process powershell.exe -WindowStyle Hidden -ArgumentList '-NoProfile -ExecutionPolicy Bypass -EncodedCommand {encodedBody}'
            """;

        var result = await powerShell.RunAsync(
            new PowerShellCommand(command),
            TimeSpan.FromSeconds(options.ScanLaunchTimeoutSeconds),
            cancellationToken);
        eventLog.RecordAction(
            "Defender scan requested",
            result.ExitCode == 0 ? "Low" : "Medium",
            result.ExitCode == 0
                ? $"{scanType} was started in the background by Microsoft Defender."
                : result.Error);
        return RecordResponse(
            "defender.scan",
            scanType,
            requestedAt,
            ToActionResult(result),
            JsonSerializer.Serialize(new
            {
                RequestedType = requestedType,
                State = "not_requested"
            }),
            JsonSerializer.Serialize(new
            {
                ScanType = scanType,
                LaunchExitCode = result.ExitCode,
                State = result.ExitCode == 0 ? "launched" : "launch_failed"
            }));
    }

    public async Task<ActionResultDto> BlockIpAsync(
        string ipAddress,
        CancellationToken cancellationToken = default)
    {
        var requestedAt = DateTimeOffset.UtcNow;
        if (options.DryRun)
        {
            return DryRun("firewall.block_ip", ipAddress, requestedAt);
        }
        var elevation = RequireAdministrator(
            "firewall.block_ip",
            ipAddress,
            requestedAt);
        if (elevation is not null)
        {
            return elevation;
        }

        var beforeBlock = ipBlocks.Find(ipAddress);
        if (!IPAddress.TryParse(ipAddress, out var ip))
        {
            return RecordResponse(
                "firewall.block_ip",
                ipAddress,
                requestedAt,
                new ActionResultDto(
                false,
                "",
                "Enter a valid IPv4 or IPv6 address."));
        }

        if (IPAddress.IsLoopback(ip))
        {
            return RecordResponse(
                "firewall.block_ip",
                ipAddress,
                requestedAt,
                new ActionResultDto(
                    false,
                    "",
                    "Loopback addresses are not blocked."));
        }

        var stamp = DateTimeOffset.Now.ToString("yyyyMMddHHmmss");
        var displayName =
            $"{options.FirewallRulePrefix} Block {ip} {stamp}";
        var command = """
            $ruleName = $env:ROAMSENTINEL_PARAM_RULE_NAME;
            $remoteIp = $env:ROAMSENTINEL_PARAM_REMOTE_IP;
            New-NetFirewallRule -DisplayName "$ruleName Outbound" -Direction Outbound -RemoteAddress $remoteIp -Action Block -Profile Any -ErrorAction Stop;
            New-NetFirewallRule -DisplayName "$ruleName Inbound" -Direction Inbound -RemoteAddress $remoteIp -Action Block -Profile Any -ErrorAction Stop
            """;

        var result = await powerShell.RunAsync(
            new PowerShellCommand(
                command,
                new Dictionary<string, string>
                {
                    ["RULE_NAME"] = displayName,
                    ["REMOTE_IP"] = ip.ToString()
                }),
            TimeSpan.FromSeconds(options.CommandTimeoutSeconds),
            cancellationToken);
        if (result.ExitCode == 0)
        {
            ipBlocks.Upsert(new IpBlockDto(
                ip.ToString(),
                displayName,
                DateTimeOffset.Now));
        }

        eventLog.RecordAction(
            "Firewall block requested",
            result.ExitCode == 0 ? "Medium" : "High",
            result.ExitCode == 0
                ? $"Windows Firewall block rules were added for {ip}."
                : result.Error);
        return RecordResponse(
            "firewall.block_ip",
            ip.ToString(),
            requestedAt,
            ToActionResult(result),
            JsonSerializer.Serialize(new
            {
                Blocked = beforeBlock is not null,
                Rule = beforeBlock?.DisplayName ?? ""
            }),
            JsonSerializer.Serialize(new
            {
                Blocked = result.ExitCode == 0,
                Rule = result.ExitCode == 0 ? displayName : ""
            }));
    }

    public async Task<ActionResultDto> UnblockIpAsync(
        string ipAddress,
        CancellationToken cancellationToken = default)
    {
        var requestedAt = DateTimeOffset.UtcNow;
        if (options.DryRun)
        {
            return DryRun("firewall.unblock_ip", ipAddress, requestedAt);
        }
        var elevation = RequireAdministrator(
            "firewall.unblock_ip",
            ipAddress,
            requestedAt);
        if (elevation is not null)
        {
            return elevation;
        }

        if (!IPAddress.TryParse(ipAddress, out var ip))
        {
            return RecordResponse(
                "firewall.unblock_ip",
                ipAddress,
                requestedAt,
                new ActionResultDto(
                false,
                "",
                "Enter a valid blocked IP address."));
        }

        var block = ipBlocks.Find(ip.ToString());
        if (block is null)
        {
            return RecordResponse(
                "firewall.unblock_ip",
                ipAddress,
                requestedAt,
                new ActionResultDto(
                false,
                "",
                "RoamSentinel has no stored block for that IP."));
        }

        var command = """
            $ruleName = $env:ROAMSENTINEL_PARAM_RULE_NAME;
            Get-NetFirewallRule -DisplayName "$ruleName Outbound" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop;
            Get-NetFirewallRule -DisplayName "$ruleName Inbound" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
            """;
        var result = await powerShell.RunAsync(
            new PowerShellCommand(
                command,
                new Dictionary<string, string>
                {
                    ["RULE_NAME"] = block.DisplayName
                }),
            TimeSpan.FromSeconds(options.CommandTimeoutSeconds),
            cancellationToken);
        if (result.ExitCode == 0)
        {
            ipBlocks.Remove(block.IpAddress);
        }

        eventLog.RecordAction(
            "IP block restored",
            result.ExitCode == 0 ? "Medium" : "High",
            result.ExitCode == 0
                ? $"Removed RoamSentinel Windows Firewall rules for {block.IpAddress}."
                : result.Error);
        return RecordResponse(
            "firewall.unblock_ip",
            block.IpAddress,
            requestedAt,
            ToActionResult(result),
            JsonSerializer.Serialize(new
            {
                Blocked = true,
                block.DisplayName
            }),
            JsonSerializer.Serialize(new
            {
                Blocked = result.ExitCode != 0,
                Rule = result.ExitCode == 0 ? "" : block.DisplayName
            }));
    }

    public Task<ActionResultDto> BlockAgentAsync(
        string path,
        CancellationToken cancellationToken = default) =>
        options.DryRun
            ? Task.FromResult(DryRun(
                "firewall.block_agent",
                path,
                DateTimeOffset.UtcNow))
            : ChangeAgentFirewallStateAsync(path, block: true, cancellationToken);

    public Task<ActionResultDto> UnblockAgentAsync(
        string path,
        CancellationToken cancellationToken = default) =>
        options.DryRun
            ? Task.FromResult(DryRun(
                "firewall.unblock_agent",
                path,
                DateTimeOffset.UtcNow))
            : ChangeAgentFirewallStateAsync(path, block: false, cancellationToken);

    public ActionResultDto KillProcess(int processId)
    {
        var requestedAt = DateTimeOffset.UtcNow;
        if (options.DryRun)
        {
            return DryRun("process.kill", processId.ToString(), requestedAt);
        }
        var elevation = RequireAdministrator(
            "process.kill",
            processId.ToString(),
            requestedAt);
        if (elevation is not null)
        {
            return elevation;
        }

        if (processId <= 0 || processId == Environment.ProcessId)
        {
            return RecordResponse(
                "process.kill",
                processId.ToString(),
                requestedAt,
                new ActionResultDto(
                false,
                "",
                "That process cannot be stopped from RoamSentinel."));
        }

        try
        {
            var process = Process.GetProcessById(processId);
            var name = process.ProcessName;
            var before = JsonSerializer.Serialize(new
            {
                ProcessId = processId,
                Name = name,
                HasExited = process.HasExited,
                WorkingSetBytes = process.WorkingSet64
            });
            process.Kill(entireProcessTree: true);
            process.WaitForExit(Math.Max(1000, options.CommandTimeoutSeconds * 1000));
            eventLog.RecordAction(
                "Process stopped",
                "High",
                $"{name} ({processId}) was stopped by user action.");
            return RecordResponse(
                "process.kill",
                $"{name}:{processId}",
                requestedAt,
                new ActionResultDto(
                    true,
                    $"{name} ({processId}) stopped.",
                    ""),
                before,
                JsonSerializer.Serialize(new
                {
                    ProcessId = processId,
                    Name = name,
                    HasExited = process.HasExited
                }));
        }
        catch (Exception ex)
        {
            return RecordResponse(
                "process.kill",
                processId.ToString(),
                requestedAt,
                new ActionResultDto(false, "", ex.Message));
        }
    }

    public async Task<ActionResultDto> QuarantineFileAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        var requestedAt = DateTimeOffset.UtcNow;
        if (options.DryRun)
        {
            return DryRun("defender.quarantine_file", path, requestedAt);
        }
        var elevation = RequireAdministrator(
            "defender.quarantine_file",
            path,
            requestedAt);
        if (elevation is not null)
        {
            return elevation;
        }

        var validation = ValidateQuarantinePath(path);
        if (!validation.Ok)
        {
            return RecordResponse(
                "defender.quarantine_file",
                path,
                requestedAt,
                validation);
        }

        var fullPath = Path.GetFullPath(path);
        var before = GetFileSnapshot(fullPath);
        var result = await powerShell.RunAsync(
            new PowerShellCommand(
                """
                $scanPath = $env:ROAMSENTINEL_PARAM_SCAN_PATH;
                Start-MpScan -ScanType CustomScan -ScanPath $scanPath -ErrorAction Stop
                """,
                new Dictionary<string, string>
                {
                    ["SCAN_PATH"] = fullPath
                }),
            TimeSpan.FromSeconds(options.FileScanTimeoutSeconds),
            cancellationToken);
        var after = GetFileSnapshot(fullPath);
        var actionResult = result.ExitCode == 0
            ? new ActionResultDto(
                true,
                File.Exists(fullPath)
                    ? "Defender completed the custom scan. The file remains present; no quarantine is claimed."
                    : "Defender completed the custom scan and the file is no longer present at the original path.",
                "")
            : ToActionResult(result);
        eventLog.RecordAction(
            "Suspicious file scanned",
            actionResult.Ok ? "High" : "Critical",
            actionResult.Ok ? actionResult.Output : actionResult.Error);
        return RecordResponse(
            "defender.quarantine_file",
            fullPath,
            requestedAt,
            actionResult,
            before,
            after);
    }

    public async Task<ActionResultDto> DisableStartupItemAsync(
        DisableStartupRequest request,
        CancellationToken cancellationToken = default)
    {
        var requestedAt = DateTimeOffset.UtcNow;
        if (options.DryRun)
        {
            return DryRun("startup.disable", request.Name, requestedAt);
        }
        var elevation = RequireAdministrator(
            "startup.disable",
            request.Name,
            requestedAt);
        if (elevation is not null)
        {
            return elevation;
        }

        if (string.IsNullOrWhiteSpace(request.Name) ||
            string.IsNullOrWhiteSpace(request.Source))
        {
            return RecordResponse(
                "startup.disable",
                request.Name ?? "",
                requestedAt,
                new ActionResultDto(
                    false,
                    "",
                    "Startup item name and source are required."));
        }

        try
        {
            if (request.Source.StartsWith(
                    "ScheduledTask:",
                    StringComparison.OrdinalIgnoreCase))
            {
                return await DisableScheduledTaskAsync(
                    request,
                    requestedAt,
                    cancellationToken);
            }

            if (request.Source.StartsWith(
                    "HKCU\\",
                    StringComparison.OrdinalIgnoreCase) ||
                request.Source.StartsWith(
                    "HKLM\\",
                    StringComparison.OrdinalIgnoreCase))
            {
                return DisableRegistryStartup(request, requestedAt);
            }

            if (request.Source is "Current user startup folder" or
                "All users startup folder")
            {
                return DisableStartupFile(request, requestedAt);
            }

            return RecordResponse(
                "startup.disable",
                request.Name,
                requestedAt,
                new ActionResultDto(
                    false,
                    "",
                    "This startup source is not supported for controlled disable."));
        }
        catch (Exception ex)
        {
            return RecordResponse(
                "startup.disable",
                request.Name,
                requestedAt,
                new ActionResultDto(false, "", ex.Message),
                JsonSerializer.Serialize(request),
                "{}");
        }
    }

    public ActionResultDto ResolveAlert(string alertId, string note) =>
        SetAlertDisposition(alertId, "resolved", note);

    public ActionResultDto MarkFalsePositive(string alertId, string note) =>
        SetAlertDisposition(alertId, "false_positive", note);

    public IReadOnlyList<AgentEgressRuleDto> GetActiveAgentEgressRules() =>
        agentEgressRules.GetAll();

    private async Task<ActionResultDto> ChangeAgentFirewallStateAsync(
        string path,
        bool block,
        CancellationToken cancellationToken)
    {
        var requestedAt = DateTimeOffset.UtcNow;
        var actionType =
            block ? "firewall.block_agent" : "firewall.unblock_agent";
        var elevation = RequireAdministrator(
            actionType,
            path,
            requestedAt);
        if (elevation is not null)
        {
            return elevation;
        }

        if (string.IsNullOrWhiteSpace(path))
        {
            return RecordResponse(
                block ? "firewall.block_agent" : "firewall.unblock_agent",
                path,
                requestedAt,
                new ActionResultDto(false, "", "Agent path is required."));
        }

        var command = block
            ? """
                $program = $env:ROAMSENTINEL_PARAM_PROGRAM_PATH;
                $currentPrefix = $env:ROAMSENTINEL_PARAM_CURRENT_PREFIX;
                $legacyPrefix = $env:ROAMSENTINEL_PARAM_LEGACY_PREFIX;
                $name = $currentPrefix + ' Agent Block ' + ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($program))).Substring(0, 24);
                Get-NetFirewallRule -DisplayName ($legacyPrefix + ' Agent Block ' + ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($program))).Substring(0, 24) + '*') -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue;
                Get-NetFirewallRule -DisplayName "$name*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue;
                New-NetFirewallRule -DisplayName "$name Outbound" -Direction Outbound -Program $program -Action Block -Profile Any -ErrorAction Stop;
                New-NetFirewallRule -DisplayName "$name Inbound" -Direction Inbound -Program $program -Action Block -Profile Any -ErrorAction Stop
                """
            : """
                $program = $env:ROAMSENTINEL_PARAM_PROGRAM_PATH;
                $currentPrefix = $env:ROAMSENTINEL_PARAM_CURRENT_PREFIX;
                $legacyPrefix = $env:ROAMSENTINEL_PARAM_LEGACY_PREFIX;
                $name = $currentPrefix + ' Agent Block ' + ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($program))).Substring(0, 24);
                Get-NetFirewallRule -DisplayName ($legacyPrefix + ' Agent Block ' + ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($program))).Substring(0, 24) + '*') -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue;
                Get-NetFirewallRule -DisplayName "$name*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
                """;

        var result = await powerShell.RunAsync(
            new PowerShellCommand(
                command,
                new Dictionary<string, string>
                {
                    ["PROGRAM_PATH"] = path,
                    ["CURRENT_PREFIX"] = options.FirewallRulePrefix,
                    ["LEGACY_PREFIX"] = options.LegacyFirewallRulePrefix
                }),
            TimeSpan.FromSeconds(options.CommandTimeoutSeconds),
            cancellationToken);

        var displayName = $"{options.FirewallRulePrefix} Agent Block {Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(path)))[..16]}";
        if (result.ExitCode == 0)
        {
            if (block)
            {
                agentEgressRules.Upsert(new AgentEgressRuleDto(
                    Guid.NewGuid().ToString("N"),
                    Path.GetFileNameWithoutExtension(path).ToLowerInvariant(),
                    path,
                    displayName,
                    "Outbound",
                    "Block",
                    DateTimeOffset.UtcNow,
                    Operator));
            }
            else
            {
                agentEgressRules.Remove(path);
            }
        }

        eventLog.RecordAction(
            block ? "Agent blocked" : "Agent block restored",
            result.ExitCode == 0 ? (block ? "High" : "Medium") : "High",
            result.ExitCode == 0
                ? block
                    ? path
                    : $"Removed RoamSentinel outbound block for {path}."
                : result.Error);
        return RecordResponse(
            block ? "firewall.block_agent" : "firewall.unblock_agent",
            path,
            requestedAt,
            ToActionResult(result),
            JsonSerializer.Serialize(new { Blocked = !block, Path = path }),
            JsonSerializer.Serialize(new
            {
                Blocked = block && result.ExitCode == 0,
                Path = path
            }));
    }

    private ActionResultDto RecordResponse(
        string actionType,
        string target,
        DateTimeOffset requestedAt,
        ActionResultDto result,
        string beforeJson = "{}",
        string afterJson = "{}")
    {
        responseActions.Record(new ResponseActionRecord(
            Guid.NewGuid().ToString("N"),
            requestedAt,
            DateTimeOffset.UtcNow,
            actionType,
            target,
            result.Ok ? "completed" : "failed",
            result.Ok,
            result.Output,
            result.Error,
            Operator,
            beforeJson,
            afterJson));
        return result;
    }

    private ActionResultDto DryRun(
        string actionType,
        string target,
        DateTimeOffset requestedAt) =>
        RecordResponse(
            actionType,
            target,
            requestedAt,
            new ActionResultDto(
                true,
                "Dry run: no system change was made.",
                ""),
            "{}",
            JsonSerializer.Serialize(new { DryRun = true, Target = target }));

    private ActionResultDto? RequireAdministrator(
        string actionType,
        string target,
        DateTimeOffset requestedAt) =>
        privileges.IsAdministrator()
            ? null
            : RecordResponse(
                actionType,
                target,
                requestedAt,
                new ActionResultDto(
                    false,
                    "",
                    "This response action requires an elevated RoamSentinel process."));

    private async Task<ActionResultDto> DisableScheduledTaskAsync(
        DisableStartupRequest request,
        DateTimeOffset requestedAt,
        CancellationToken cancellationToken)
    {
        var taskPath = request.Source["ScheduledTask:".Length..].Trim();
        if (!taskPath.StartsWith('\\'))
        {
            taskPath = $"\\{taskPath}";
        }

        if (taskPath.StartsWith(
                @"\Microsoft\Windows\",
                StringComparison.OrdinalIgnoreCase))
        {
            return RecordResponse(
                "startup.disable",
                $"{taskPath}{request.Name}",
                requestedAt,
                new ActionResultDto(
                    false,
                    "",
                    "Built-in Microsoft Windows scheduled tasks are protected."));
        }

        var command = """
            $taskName = $env:ROAMSENTINEL_PARAM_TASK_NAME;
            $taskPath = $env:ROAMSENTINEL_PARAM_TASK_PATH;
            $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop;
            $before = $task | Select-Object TaskName, TaskPath, State | ConvertTo-Json -Compress;
            Disable-ScheduledTask -InputObject $task -ErrorAction Stop | Out-Null;
            $after = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath | Select-Object TaskName, TaskPath, State | ConvertTo-Json -Compress;
            Write-Output ($before + [Environment]::NewLine + $after)
            """;
        var result = await powerShell.RunAsync(
            new PowerShellCommand(
                command,
                new Dictionary<string, string>
                {
                    ["TASK_NAME"] = request.Name,
                    ["TASK_PATH"] = taskPath
                }),
            TimeSpan.FromSeconds(options.CommandTimeoutSeconds),
            cancellationToken);
        var before = JsonSerializer.Serialize(new
        {
            Type = "scheduled_task",
            TaskName = request.Name,
            TaskPath = taskPath,
            Enabled = true
        });
        var after = JsonSerializer.Serialize(new
        {
            Type = "scheduled_task",
            TaskName = request.Name,
            TaskPath = taskPath,
            Enabled = result.ExitCode != 0
        });
        if (result.ExitCode == 0)
        {
            disabledStartup.Record(new DisabledStartupItemRecord(
                Guid.NewGuid().ToString("N"),
                "scheduled_task",
                taskPath,
                request.Name,
                request.Command ?? "",
                "",
                DateTimeOffset.UtcNow,
                Operator));
        }

        return RecordResponse(
            "startup.disable",
            $"{taskPath}{request.Name}",
            requestedAt,
            ToActionResult(result),
            before,
            after);
    }

    private ActionResultDto DisableRegistryStartup(
        DisableStartupRequest request,
        DateTimeOffset requestedAt)
    {
        var currentUser = request.Source.StartsWith(
            "HKCU\\",
            StringComparison.OrdinalIgnoreCase);
        var subKey = request.Source[5..];
        if (!subKey.Equals(
                @"Software\Microsoft\Windows\CurrentVersion\Run",
                StringComparison.OrdinalIgnoreCase))
        {
            return RecordResponse(
                "startup.disable",
                request.Name,
                requestedAt,
                new ActionResultDto(
                    false,
                    "",
                    "Only the standard Windows Run registry keys can be changed."));
        }

        using var hive = currentUser
            ? Registry.CurrentUser
            : Registry.LocalMachine;
        using var key = hive.OpenSubKey(subKey, writable: true);
        var original = key?.GetValue(request.Name)?.ToString();
        if (key is null || original is null)
        {
            return RecordResponse(
                "startup.disable",
                request.Name,
                requestedAt,
                new ActionResultDto(false, "", "Startup registry value was not found."));
        }

        var before = JsonSerializer.Serialize(new
        {
            Type = "registry",
            request.Source,
            request.Name,
            Value = original,
            Exists = true
        });
        key.DeleteValue(request.Name, throwOnMissingValue: true);
        disabledStartup.Record(new DisabledStartupItemRecord(
            Guid.NewGuid().ToString("N"),
            "registry",
            request.Source,
            request.Name,
            original,
            "",
            DateTimeOffset.UtcNow,
            Operator));
        return RecordResponse(
            "startup.disable",
            $"{request.Source}\\{request.Name}",
            requestedAt,
            new ActionResultDto(
                true,
                $"Disabled startup registry item {request.Name}.",
                ""),
            before,
            JsonSerializer.Serialize(new
            {
                Type = "registry",
                request.Source,
                request.Name,
                Exists = false
            }));
    }

    private ActionResultDto DisableStartupFile(
        DisableStartupRequest request,
        DateTimeOffset requestedAt)
    {
        var sourcePath = Path.GetFullPath(request.Command ?? "");
        var expectedFolder = request.Source == "Current user startup folder"
            ? Environment.GetFolderPath(Environment.SpecialFolder.Startup)
            : Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
        if (string.IsNullOrWhiteSpace(expectedFolder) ||
            !string.Equals(
                Path.GetDirectoryName(sourcePath),
                Path.GetFullPath(expectedFolder),
                StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(sourcePath))
        {
            return RecordResponse(
                "startup.disable",
                request.Name,
                requestedAt,
                new ActionResultDto(
                    false,
                    "",
                    "Startup file is missing or outside the selected startup folder."));
        }

        var disabledFolder = Path.Combine(expectedFolder, "RoamSentinel Disabled");
        Directory.CreateDirectory(disabledFolder);
        var backupPath = Path.Combine(
            disabledFolder,
            $"{Guid.NewGuid():N}-{Path.GetFileName(sourcePath)}");
        var before = GetFileSnapshot(sourcePath);
        File.Move(sourcePath, backupPath);
        disabledStartup.Record(new DisabledStartupItemRecord(
            Guid.NewGuid().ToString("N"),
            "startup_folder",
            request.Source,
            request.Name,
            sourcePath,
            backupPath,
            DateTimeOffset.UtcNow,
            Operator));
        return RecordResponse(
            "startup.disable",
            sourcePath,
            requestedAt,
            new ActionResultDto(
                true,
                $"Moved startup item to {backupPath}.",
                ""),
            before,
            JsonSerializer.Serialize(new
            {
                OriginalPath = sourcePath,
                OriginalExists = File.Exists(sourcePath),
                BackupPath = backupPath,
                BackupExists = File.Exists(backupPath)
            }));
    }

    private ActionResultDto SetAlertDisposition(
        string alertId,
        string status,
        string note)
    {
        var requestedAt = DateTimeOffset.UtcNow;
        if (string.IsNullOrWhiteSpace(alertId))
        {
            return RecordResponse(
                $"alert.{status}",
                "",
                requestedAt,
                new ActionResultDto(false, "", "Alert ID is required."));
        }

        var before = events.GetState(alertId);
        if (before is null)
        {
            return RecordResponse(
                $"alert.{status}",
                alertId,
                requestedAt,
                new ActionResultDto(false, "", "Alert was not found."));
        }

        var after = events.SetDisposition(
            alertId,
            status,
            note?.Trim() ?? "",
            Operator);
        var result = after is null
            ? new ActionResultDto(false, "", "Alert state could not be updated.")
            : new ActionResultDto(true, $"Alert marked {status}.", "");
        return RecordResponse(
            $"alert.{status}",
            alertId,
            requestedAt,
            result,
            JsonSerializer.Serialize(before),
            JsonSerializer.Serialize(after));
    }

    private static ActionResultDto ValidateQuarantinePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
        {
            return new ActionResultDto(
                false,
                "",
                "An absolute file path is required.");
        }

        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath))
        {
            return new ActionResultDto(false, "", "The file does not exist.");
        }

        var attributes = File.GetAttributes(fullPath);
        if (attributes.HasFlag(FileAttributes.Directory) ||
            attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            return new ActionResultDto(
                false,
                "",
                "Directories and reparse points cannot be submitted.");
        }

        var userProfile = Path.GetFullPath(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
        var temp = Path.GetFullPath(Path.GetTempPath());
        if (!IsUnder(fullPath, userProfile) && !IsUnder(fullPath, temp))
        {
            return new ActionResultDto(
                false,
                "",
                "For safety, file response is limited to the current user profile and temporary directory.");
        }

        return new ActionResultDto(true, "", "");
    }

    private static string GetFileSnapshot(string path)
    {
        if (!File.Exists(path))
        {
            return JsonSerializer.Serialize(new { Path = path, Exists = false });
        }

        var info = new FileInfo(path);
        using var stream = File.OpenRead(path);
        var hash = Convert.ToHexString(SHA256.HashData(stream));
        return JsonSerializer.Serialize(new
        {
            Path = path,
            Exists = true,
            info.Length,
            Sha256 = hash,
            Attributes = info.Attributes.ToString(),
            info.LastWriteTimeUtc
        });
    }

    private static bool IsUnder(string path, string root)
    {
        var normalizedRoot = root.TrimEnd(
            Path.DirectorySeparatorChar,
            Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return path.StartsWith(
            normalizedRoot,
            StringComparison.OrdinalIgnoreCase);
    }

    private static ActionResultDto ToActionResult(CommandResult result) =>
        new(result.ExitCode == 0, result.Output, result.Error);

}
