using RoamSentinel.Config;
using RoamSentinel.Core;
using RoamSentinel.Telemetry;

namespace RoamSentinel.Tests;

public sealed class TelemetryCollectorTests
{
    [Fact]
    public void FindSuspiciousPaths_NormalizesEvidenceWithoutRiskScoring()
    {
        var collector = new AgentInstallationCollector(
            new NoAgentIdentityService(),
            new TelemetryOptions());
        var processes = new[]
        {
            new ProcessTelemetry(
                10,
                "runner",
                @"C:\Users\User\AppData\Roaming\runner.exe",
                10,
                8,
                0,
                5,
                2,
                0,
                DateTimeOffset.UtcNow)
        };

        var observations = collector.FindSuspiciousPaths(
            processes,
            [],
            [],
            [],
            []);

        var observation = Assert.Single(observations);
        Assert.Equal("Process", observation.SourceType);
        Assert.Equal(processes[0].Path, observation.Path);
        Assert.Contains(
            "configured user-writable marker",
            observation.Reason,
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task DeviceIntegrityInventory_NormalizesWindowsObservations()
    {
        const string json = """
            {
              "Drivers": [{
                "Name": "WdFilter",
                "DisplayName": "Defender Filter",
                "State": "Running",
                "StartMode": "Boot",
                "PathName": "C:\\Windows\\System32\\drivers\\WdFilter.sys",
                "ServiceType": "File System Driver"
              }],
              "Software": [{
                "DisplayName": "Example Tool",
                "DisplayVersion": "1.2.3",
                "Publisher": "Example",
                "InstallLocation": "C:\\Program Files\\Example",
                "RegistrySource": "HKLM"
              }],
              "Persistence": [{
                "Hive": "HKLM",
                "Key": "HKLM:\\Software\\...\\Run",
                "Name": "Updater",
                "Value": "updater.exe"
              }],
              "Files": [{
                "FullName": "C:\\ProgramData\\Startup\\item.cmd",
                "Length": 42,
                "LastWriteTimeUtc": "2026-07-07T00:00:00Z",
                "Extension": ".cmd"
              }],
              "Services": [{
                "Name": "WinDefend",
                "DisplayName": "Microsoft Defender Antivirus Service",
                "State": "Running",
                "StartMode": "Auto",
                "PathName": "C:\\Program Files\\Windows Defender\\MsMpEng.exe",
                "ProcessId": 200,
                "StartName": "LocalSystem"
              }],
              "ScheduledTasks": [{
                "Name": "ExampleTask",
                "Path": "\\Microsoft\\RoamSentinel\\",
                "State": "Ready",
                "Enabled": true,
                "Author": "SYSTEM",
                "Command": "powershell.exe",
                "Arguments": "-NoProfile",
                "Trigger": "At logon"
              }],
              "FirewallProfiles": [{
                "Name": "Domain",
                "Enabled": true,
                "DefaultInboundAction": "Block",
                "DefaultOutboundAction": "Allow",
                "NotifyOnListen": true
              }],
              "NetworkListeners": [{
                "Protocol": "TCP",
                "LocalAddress": "127.0.0.1",
                "LocalPort": 5117,
                "ProcessId": 300,
                "ProcessName": "RoamSentinel",
                "ProcessPath": "C:\\Program Files\\RoamSentinel\\RoamSentinel.exe"
              }],
              "PowerShell": {
                "ExecutionPolicy": "RemoteSigned",
                "ScriptBlockLogging": true,
                "ModuleLogging": false,
                "Transcription": true,
                "Version": "5.1"
              }
            }
            """;
        var runner = new FixedPowerShellRunner(
            new CommandResult(0, json, ""));
        var service = new DeviceIntegrityInventoryService(
            runner,
            new TelemetryOptions
            {
                MonitoredFileDirectories = [@"C:\Monitored"],
                DeviceIntegrityFileLimit = 25
            });

        var snapshot = await service.CollectAsync();

        Assert.Equal("WdFilter", Assert.Single(snapshot.Drivers).Name);
        Assert.Equal("Example Tool", Assert.Single(
            snapshot.InstalledSoftware).Name);
        Assert.Equal("Updater", Assert.Single(
            snapshot.RegistryPersistence).Name);
        Assert.Equal(42, Assert.Single(snapshot.MonitoredFiles).Length);
        Assert.Equal("WinDefend", Assert.Single(snapshot.Services).Name);
        Assert.Equal("ExampleTask", Assert.Single(snapshot.ScheduledTasks).Name);
        Assert.Equal("Domain", Assert.Single(snapshot.FirewallProfiles).Name);
        Assert.Equal(5117, Assert.Single(snapshot.NetworkListeners).LocalPort);
        Assert.True(snapshot.PowerShell.ScriptBlockLogging);
        Assert.True(snapshot.PowerShell.Transcription);
        Assert.Empty(snapshot.CollectionErrors);
        Assert.Equal(
            "25",
            runner.Command?.Parameters?["FILE_LIMIT"]);
        Assert.Contains(
            @"C:\\Monitored",
            runner.Command?.Parameters?["MONITORED_PATHS"] ?? "");
    }

    [Fact]
    public async Task DeviceIntegrityInventory_ReturnsCollectionErrorSafely()
    {
        var service = new DeviceIntegrityInventoryService(
            new FixedPowerShellRunner(
                new CommandResult(1, "", "CIM unavailable")),
            new TelemetryOptions());

        var snapshot = await service.CollectAsync();

        Assert.Empty(snapshot.Drivers);
        Assert.Contains("CIM unavailable", snapshot.CollectionErrors);
    }

    private sealed class NoAgentIdentityService : IAgentIdentityService
    {
        public AgentIdentityDto Identify(
            string name,
            string path,
            string commandLine = "") =>
            new(false, "", "", "", false, false);
    }

    private sealed class FixedPowerShellRunner(CommandResult result)
        : IPowerShellRunner
    {
        public PowerShellCommand? Command { get; private set; }

        public Task<CommandResult> RunAsync(
            PowerShellCommand command,
            TimeSpan timeout,
            CancellationToken cancellationToken = default)
        {
            Command = command;
            return Task.FromResult(result);
        }
    }
}
