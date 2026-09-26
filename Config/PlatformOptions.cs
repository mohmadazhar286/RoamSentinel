namespace RoamSentinel.Config;

public sealed class RoamSentinelOptions
{
    public string BindUrl { get; init; } = "http://127.0.0.1:5117";
}

public sealed class DatabaseOptions
{
    public string FilePath { get; init; } = "roamsentinel.db";
    public int CommandTimeoutSeconds { get; init; } = 30;
    public int BusyTimeoutMilliseconds { get; init; } = 5000;
    public bool ImportLegacyJson { get; init; } = true;
    public bool PersistTelemetrySnapshots { get; init; } = true;
    public int TelemetryPersistenceIntervalSeconds { get; init; } = 300;
    public int TelemetryRetentionDays { get; init; } = 7;
}

public sealed class TelemetryOptions
{
    public int CollectionIntervalSeconds { get; init; } = 8;
    public int ConnectionCommandTimeoutSeconds { get; init; } = 12;
    public int DefenderCommandTimeoutSeconds { get; init; } = 10;
    public int InventoryCommandTimeoutSeconds { get; init; } = 20;
    public int DeviceIntegrityCommandTimeoutSeconds { get; init; } = 60;
    public int DeviceIntegrityIntervalSeconds { get; init; } = 300;
    public int DeviceIntegrityFileLimit { get; init; } = 500;
    public string[] MonitoredFileDirectories { get; init; } = [];
    public string[] SuspiciousPathMarkers { get; init; } =
        [@"\appdata\local\temp\", @"\appdata\roaming\", @"\downloads\", @"\users\public\"];
}

public sealed class DetectionOptions
{
    public int FindingPersistenceIntervalSeconds { get; init; } = 60;
    public int CriticalSeverityScore { get; init; } = 90;
    public int HighSeverityScore { get; init; } = 70;
    public int MediumSeverityScore { get; init; } = 45;
    public int LowSeverityScore { get; init; } = 20;
    public int ConnectionAlertMinimumScore { get; init; } = 55;
    public int ProcessAlertMinimumScore { get; init; } = 50;
    public int StartupAlertMinimumScore { get; init; } = 40;
    public int MaxAlertsPerCategory { get; init; } = 30;
    public int StaleQuickScanDays { get; init; } = 7;
    public int ManyConnectionsThreshold { get; init; } = 25;
    public int PublicConnectionScore { get; init; } = 20;
    public int SensitivePortScore { get; init; } = 35;
    public int ScriptableProcessScore { get; init; } = 35;
    public int UserWritablePathScore { get; init; } = 25;
    public int AgentUnauthorizedScore { get; init; } = 80;
    public int StartupUserWritableScore { get; init; } = 40;
    public int StartupScriptScore { get; init; } = 35;
    public int[] SensitivePorts { get; init; } =
        [23, 2323, 4444, 5555, 6667, 1337, 31337, 3389, 5900];
    public string[] ScriptableProcesses { get; init; } =
        ["powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "cmd"];
    public string[] UserWritablePathMarkers { get; init; } =
        [@"\appdata\local\temp\", @"\appdata\roaming\", @"\downloads\", @"\users\public\"];
}

public sealed class ResponseOptions
{
    public bool DryRun { get; init; }
    public int CommandTimeoutSeconds { get; init; } = 25;
    public int ScanLaunchTimeoutSeconds { get; init; } = 8;
    public int FileScanTimeoutSeconds { get; init; } = 120;
    public string OperatorToken { get; init; } = "";
    public string FirewallRulePrefix { get; init; } = "RoamSentinel";
    public string LegacyFirewallRulePrefix { get; init; } = "RoamSentinel Legacy";
}

public sealed class AgentGovernanceOptions
{
    public string[] IdentityMarkers { get; init; } =
        ["codex", "chatgpt", "claude", "anthropic", "cursor", "windsurf",
         "aider", "openhands", "roo-code", "roo-cline", "cline",
         "github.copilot", "copilot-language-server"];
    public string[] UserWritablePathMarkers { get; init; } =
        [@"\users\", @"\appdata\", @"\temp\", @"\downloads\"];
    public int ObservationPersistenceIntervalSeconds { get; init; } = 60;
    public int UnusualRemoteAddressThreshold { get; init; } = 8;
    public int TrustedPathRiskScore { get; init; } = 10;
    public int UnknownPathRiskScore { get; init; } = 55;
    public int UserWritablePathRiskScore { get; init; } = 70;
    public int UnusualNetworkRiskScore { get; init; } = 80;
    public int BlockedRunningRiskScore { get; init; } = 100;
}

public sealed class AccessControlOptions
{
    public string ViewerToken { get; init; } = "";
    public string AnalystToken { get; init; } = "";
    public string AdministratorToken { get; init; } = "";
    public int SessionMinutes { get; init; } = 30;
    public string SessionCookieName { get; init; } = "RoamSentinel.Session";
    public string CsrfHeaderName { get; init; } = "X-RoamSentinel-CSRF";
}

public sealed class StructuredLoggingOptions
{
    public string Directory { get; init; } = ".";
    public int RetentionDays { get; init; } = 7;
}

public class ThreatIntelProviderOptions
{
    public bool Enabled { get; init; }
    public string ApiKey { get; init; } = "";
    public string BaseUrl { get; init; } = "";
}

public sealed class MispProviderOptions : ThreatIntelProviderOptions
{
    public bool VerifyTls { get; init; } = true;
}

public sealed class ThreatIntelOptions
{
    public int RequestTimeoutSeconds { get; init; } = 15;
    public int CacheMinutes { get; init; } = 360;
    public int VirusTotalMaliciousThreshold { get; init; } = 3;
    public int AbuseIpDbMaxAgeDays { get; init; } = 90;
    public ThreatIntelProviderOptions VirusTotal { get; init; } = new()
    {
        BaseUrl = "https://www.virustotal.com"
    };
    public ThreatIntelProviderOptions AbuseIpDb { get; init; } = new()
    {
        BaseUrl = "https://api.abuseipdb.com"
    };
    public ThreatIntelProviderOptions AlienVaultOtx { get; init; } = new()
    {
        BaseUrl = "https://otx.alienvault.com"
    };
    public MispProviderOptions Misp { get; init; } = new();
}

public sealed class DashboardOptions
{
    public int RefreshIntervalMilliseconds { get; init; } = 8000;
    public int HeavyMemoryThresholdMb { get; init; } = 500;
    public int HeavyCpuThresholdPercent { get; init; } = 10;
    public int TopProcessLimit { get; init; } = 20;
    public int EventReviewLimit { get; init; } = 500;
    public int MemoryWarningPercent { get; init; } = 70;
    public int MemoryDangerPercent { get; init; } = 85;
}

public sealed class SchedulerOptions
{
    public bool Enabled { get; init; } = true;
    public int LoopIntervalSeconds { get; init; } = 30;
    public int TelemetrySnapshotIntervalSeconds { get; init; } = 300;
    public int AppActivityIntervalSeconds { get; init; } = 900;
    public int MalwarePostureIntervalSeconds { get; init; } = 1800;
    public int QuickScanIntervalHours { get; init; } = 24;
    public int FullScanIntervalDays { get; init; } = 7;
    public bool EnableScheduledQuickScan { get; init; } = false;
    public bool EnableScheduledFullScan { get; init; } = false;
    public int RetentionCheckIntervalHours { get; init; } = 24;
    public int WeeklyReviewIntervalDays { get; init; } = 7;
}

public sealed record PlatformOptions(
    RoamSentinelOptions Host,
    DatabaseOptions Database,
    TelemetryOptions Telemetry,
    DetectionOptions Detection,
    ResponseOptions Response,
    AgentGovernanceOptions AgentGovernance,
    AccessControlOptions AccessControl,
    StructuredLoggingOptions StructuredLogging,
    ThreatIntelOptions ThreatIntel,
    DashboardOptions Dashboard,
    SchedulerOptions Scheduler);
