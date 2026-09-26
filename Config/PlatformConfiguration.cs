namespace RoamSentinel.Config;

public static class PlatformConfiguration
{
    public static PlatformOptions Load(IConfiguration configuration)
    {
        var options = new PlatformOptions(
            configuration.GetSection("RoamSentinel").Get<RoamSentinelOptions>()
                ?? new RoamSentinelOptions(),
            configuration.GetSection("Database").Get<DatabaseOptions>()
                ?? new DatabaseOptions(),
            configuration.GetSection("Telemetry").Get<TelemetryOptions>()
                ?? new TelemetryOptions(),
            configuration.GetSection("Detection").Get<DetectionOptions>()
                ?? new DetectionOptions(),
            configuration.GetSection("Response").Get<ResponseOptions>()
                ?? new ResponseOptions(),
            configuration.GetSection("AgentGovernance").Get<AgentGovernanceOptions>()
                ?? new AgentGovernanceOptions(),
            configuration.GetSection("AccessControl").Get<AccessControlOptions>()
                ?? new AccessControlOptions(),
            configuration.GetSection("StructuredLogging").Get<StructuredLoggingOptions>()
                ?? new StructuredLoggingOptions(),
            configuration.GetSection("ThreatIntel").Get<ThreatIntelOptions>()
                ?? new ThreatIntelOptions(),
            configuration.GetSection("Dashboard").Get<DashboardOptions>()
                ?? new DashboardOptions(),
            configuration.GetSection("Scheduler").Get<SchedulerOptions>()
                ?? new SchedulerOptions());

        Validate(options);
        return options;
    }

    private static void Validate(PlatformOptions options)
    {
        if (!Uri.TryCreate(options.Host.BindUrl, UriKind.Absolute, out var bindUri) ||
            bindUri.Host is not "127.0.0.1" and not "localhost")
        {
            throw new InvalidOperationException(
                "RoamSentinel:BindUrl must be an absolute loopback URL.");
        }

        RequirePositive(options.Database.CommandTimeoutSeconds, "Database:CommandTimeoutSeconds");
        RequirePositive(options.Database.BusyTimeoutMilliseconds, "Database:BusyTimeoutMilliseconds");
        RequirePositive(
            options.Database.TelemetryPersistenceIntervalSeconds,
            "Database:TelemetryPersistenceIntervalSeconds");
        RequirePositive(
            options.Database.TelemetryRetentionDays,
            "Database:TelemetryRetentionDays");
        RequirePositive(options.Telemetry.CollectionIntervalSeconds, "Telemetry:CollectionIntervalSeconds");
        RequirePositive(options.Telemetry.ConnectionCommandTimeoutSeconds, "Telemetry:ConnectionCommandTimeoutSeconds");
        RequirePositive(options.Telemetry.DefenderCommandTimeoutSeconds, "Telemetry:DefenderCommandTimeoutSeconds");
        RequirePositive(options.Telemetry.InventoryCommandTimeoutSeconds, "Telemetry:InventoryCommandTimeoutSeconds");
        RequirePositive(
            options.Telemetry.DeviceIntegrityCommandTimeoutSeconds,
            "Telemetry:DeviceIntegrityCommandTimeoutSeconds");
        RequirePositive(
            options.Telemetry.DeviceIntegrityIntervalSeconds,
            "Telemetry:DeviceIntegrityIntervalSeconds");
        RequirePositive(
            options.Telemetry.DeviceIntegrityFileLimit,
            "Telemetry:DeviceIntegrityFileLimit");
        RequirePositive(options.Response.CommandTimeoutSeconds, "Response:CommandTimeoutSeconds");
        RequirePositive(options.Response.ScanLaunchTimeoutSeconds, "Response:ScanLaunchTimeoutSeconds");
        RequirePositive(options.Response.FileScanTimeoutSeconds, "Response:FileScanTimeoutSeconds");
        RequirePositive(
            options.AgentGovernance.ObservationPersistenceIntervalSeconds,
            "AgentGovernance:ObservationPersistenceIntervalSeconds");
        RequirePositive(
            options.AccessControl.SessionMinutes,
            "AccessControl:SessionMinutes");
        RequirePositive(
            options.StructuredLogging.RetentionDays,
            "StructuredLogging:RetentionDays");
        RequirePositive(
            options.AgentGovernance.UnusualRemoteAddressThreshold,
            "AgentGovernance:UnusualRemoteAddressThreshold");
        RequirePercentage(
            options.AgentGovernance.TrustedPathRiskScore,
            "AgentGovernance:TrustedPathRiskScore");
        RequirePercentage(
            options.AgentGovernance.UnknownPathRiskScore,
            "AgentGovernance:UnknownPathRiskScore");
        RequirePercentage(
            options.AgentGovernance.UserWritablePathRiskScore,
            "AgentGovernance:UserWritablePathRiskScore");
        RequirePercentage(
            options.AgentGovernance.UnusualNetworkRiskScore,
            "AgentGovernance:UnusualNetworkRiskScore");
        RequirePercentage(
            options.AgentGovernance.BlockedRunningRiskScore,
            "AgentGovernance:BlockedRunningRiskScore");
        RequirePositive(options.Dashboard.RefreshIntervalMilliseconds, "Dashboard:RefreshIntervalMilliseconds");
        RequirePositive(options.Dashboard.TopProcessLimit, "Dashboard:TopProcessLimit");
        RequirePositive(options.Dashboard.EventReviewLimit, "Dashboard:EventReviewLimit");
        RequirePositive(
            options.Detection.FindingPersistenceIntervalSeconds,
            "Detection:FindingPersistenceIntervalSeconds");
        RequirePositive(
            options.ThreatIntel.RequestTimeoutSeconds,
            "ThreatIntel:RequestTimeoutSeconds");
        RequirePositive(
            options.ThreatIntel.CacheMinutes,
            "ThreatIntel:CacheMinutes");
        RequirePositive(
            options.ThreatIntel.VirusTotalMaliciousThreshold,
            "ThreatIntel:VirusTotalMaliciousThreshold");
        RequirePositive(
            options.ThreatIntel.AbuseIpDbMaxAgeDays,
            "ThreatIntel:AbuseIpDbMaxAgeDays");
        RequirePercentage(
            options.Dashboard.MemoryWarningPercent,
            "Dashboard:MemoryWarningPercent");
        RequirePercentage(
            options.Dashboard.MemoryDangerPercent,
            "Dashboard:MemoryDangerPercent");
        RequirePositive(
            options.Scheduler.LoopIntervalSeconds,
            "Scheduler:LoopIntervalSeconds");
        RequirePositive(
            options.Scheduler.TelemetrySnapshotIntervalSeconds,
            "Scheduler:TelemetrySnapshotIntervalSeconds");
        RequirePositive(
            options.Scheduler.AppActivityIntervalSeconds,
            "Scheduler:AppActivityIntervalSeconds");
        RequirePositive(
            options.Scheduler.MalwarePostureIntervalSeconds,
            "Scheduler:MalwarePostureIntervalSeconds");
        RequirePositive(
            options.Scheduler.QuickScanIntervalHours,
            "Scheduler:QuickScanIntervalHours");
        RequirePositive(
            options.Scheduler.FullScanIntervalDays,
            "Scheduler:FullScanIntervalDays");
        RequirePositive(
            options.Scheduler.RetentionCheckIntervalHours,
            "Scheduler:RetentionCheckIntervalHours");
        RequirePositive(
            options.Scheduler.WeeklyReviewIntervalDays,
            "Scheduler:WeeklyReviewIntervalDays");

        if (options.Dashboard.MemoryWarningPercent >=
            options.Dashboard.MemoryDangerPercent)
        {
            throw new InvalidOperationException(
                "Dashboard memory warning threshold must be below danger threshold.");
        }

        if (string.IsNullOrWhiteSpace(options.Database.FilePath))
        {
            throw new InvalidOperationException("Database:FilePath cannot be empty.");
        }

        if (string.IsNullOrWhiteSpace(options.StructuredLogging.Directory))
        {
            throw new InvalidOperationException(
                "StructuredLogging:Directory cannot be empty.");
        }

        ValidateToken(
            options.AccessControl.ViewerToken,
            "AccessControl:ViewerToken");
        ValidateToken(
            options.AccessControl.AnalystToken,
            "AccessControl:AnalystToken");
        ValidateToken(
            options.AccessControl.AdministratorToken,
            "AccessControl:AdministratorToken");
        ValidateToken(
            options.Response.OperatorToken,
            "Response:OperatorToken");
        if (string.IsNullOrWhiteSpace(
                options.AccessControl.SessionCookieName) ||
            string.IsNullOrWhiteSpace(options.AccessControl.CsrfHeaderName))
        {
            throw new InvalidOperationException(
                "Access-control cookie and CSRF header names are required.");
        }

        if (options.Detection.SensitivePorts.Any(port => port is < 1 or > 65535))
        {
            throw new InvalidOperationException(
                "Detection:SensitivePorts must contain valid TCP/UDP ports.");
        }

        if (options.Detection.LowSeverityScore < 1 ||
            options.Detection.LowSeverityScore >=
                options.Detection.MediumSeverityScore ||
            options.Detection.MediumSeverityScore >=
                options.Detection.HighSeverityScore ||
            options.Detection.HighSeverityScore >=
                options.Detection.CriticalSeverityScore ||
            options.Detection.CriticalSeverityScore > 100)
        {
            throw new InvalidOperationException(
                "Detection severity thresholds must increase from Low through Critical and remain within 1-100.");
        }

        ValidateProviderUrl(
            options.ThreatIntel.VirusTotal,
            "ThreatIntel:VirusTotal:BaseUrl");
        ValidateProviderUrl(
            options.ThreatIntel.AbuseIpDb,
            "ThreatIntel:AbuseIpDb:BaseUrl");
        ValidateProviderUrl(
            options.ThreatIntel.AlienVaultOtx,
            "ThreatIntel:AlienVaultOtx:BaseUrl");
        if (options.ThreatIntel.Misp.Enabled)
        {
            ValidateProviderUrl(
                options.ThreatIntel.Misp,
                "ThreatIntel:Misp:BaseUrl");
        }
    }

    private static void RequirePositive(int value, string key)
    {
        if (value <= 0)
        {
            throw new InvalidOperationException($"{key} must be positive.");
        }
    }

    private static void RequirePercentage(int value, string key)
    {
        if (value is < 1 or > 100)
        {
            throw new InvalidOperationException(
                $"{key} must be between 1 and 100.");
        }
    }

    private static void ValidateProviderUrl(
        ThreatIntelProviderOptions provider,
        string key)
    {
        if (!Uri.TryCreate(provider.BaseUrl, UriKind.Absolute, out var uri) ||
            uri.Scheme is not "https" and not "http")
        {
            throw new InvalidOperationException(
                $"{key} must be an absolute HTTP or HTTPS URL.");
        }
    }

    private static void ValidateToken(string token, string key)
    {
        if (!string.IsNullOrEmpty(token) &&
            token.Length is < 16 or > 512)
        {
            throw new InvalidOperationException(
                $"{key} must be empty or between 16 and 512 characters.");
        }
    }
}
