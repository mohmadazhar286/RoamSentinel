namespace RoamSentinel.Core;

public sealed record ModuleRegistration(
    string Id,
    string Name,
    string ProductComponent,
    string Status,
    IReadOnlyList<string> Capabilities);

public sealed record ModuleExperienceDto(
    string ModuleId,
    string DisplayName,
    string ProductComponent,
    string Workspace,
    string DefaultView,
    IReadOnlyList<string> Views,
    IReadOnlyList<string> ReadEndpoints,
    IReadOnlyList<string> WriteEndpoints,
    IReadOnlyList<string> Capabilities,
    string IsolationStatus,
    string Description);

public sealed record ModuleWorkspaceDto(
    string Id,
    string Label,
    string Summary,
    string DefaultView,
    IReadOnlyList<string> Modules,
    IReadOnlyList<string> Views);

public sealed record ModuleExperienceManifestDto(
    string SchemaVersion,
    DateTimeOffset GeneratedAt,
    IReadOnlyList<ModuleWorkspaceDto> Workspaces,
    IReadOnlyList<ModuleExperienceDto> Modules);

public sealed record CodeGateScanRequest(
    string Source,
    string Revision,
    string ImportPath);

public sealed record CodeGateScanResult(
    string Verdict,
    int RiskScore,
    IReadOnlyList<string> Findings,
    DateTimeOffset EvaluatedAt);

public sealed record CodeGatePathScanRequest(
    string Path,
    string Source,
    string Revision);

public sealed record CodeGateFindingDto(
    string FindingId,
    string RuleId,
    string Severity,
    int RiskScore,
    string FilePath,
    string Evidence,
    string Explanation);

public sealed record CodeGateSubmissionDto(
    string SubmissionId,
    DateTimeOffset EvaluatedAt,
    string Actor,
    string Source,
    string Revision,
    string ImportPath,
    string Verdict,
    int RiskScore,
    int FileCount,
    string ContentSha256,
    IReadOnlyList<CodeGateFindingDto> Findings);

public sealed record CodeGateGitPushRequest(
    string RepositoryPath,
    string RepositoryName,
    string RefName,
    string Branch,
    string OldRevision,
    string NewRevision,
    string ScanPath,
    IReadOnlyList<string> ChangedFiles);

public sealed record CodeGateGitPushAuditDto(
    string AuditId,
    DateTimeOffset ObservedAt,
    string Actor,
    string RepositoryPath,
    string RepositoryName,
    string RefName,
    string Branch,
    string OldRevision,
    string NewRevision,
    string SubmissionId,
    string Verdict,
    int RiskScore,
    IReadOnlyList<string> ChangedFiles);

public sealed record CodeGateBundleImportRequest(
    string Path,
    string ExpectedSha256);

public sealed record CodeGateBundleDto(
    string BundleId,
    DateTimeOffset ImportedAt,
    string Component,
    string BundleType,
    string Name,
    string Version,
    string SchemaVersion,
    DateTimeOffset GeneratedAt,
    string Source,
    string Sha256,
    string Signature,
    bool Verified,
    string Status,
    string Message,
    string ImportedBy);

public sealed record PersonalProtectionControlDto(
    string Id,
    string Category,
    string Name,
    string Status,
    string Enforcement,
    string OperatorAction);

public sealed record PersonalProtectionProfileDto(
    DateTimeOffset GeneratedAt,
    string Mode,
    string Scope,
    IReadOnlyList<PersonalProtectionControlDto> Controls);

public sealed record InsiderRiskSummaryDto(
    DateTimeOffset GeneratedAt,
    int RiskScore,
    string Severity,
    IReadOnlyList<string> Signals);

public sealed record MobilePairingSessionDto(
    string PairingId,
    string PairingCode,
    DateTimeOffset CreatedAt,
    DateTimeOffset ExpiresAt,
    string Status)
{
    public string PairingPayload { get; init; } = "";
    public string PairingScheme { get; init; } = "rs://pair";
    public string PairingBaseUrl { get; init; } = "";
}

public sealed record MobileDeviceDto(
    string DeviceId,
    string DisplayName,
    string Platform,
    string Manufacturer,
    string Model,
    string OsVersion,
    string AppVersion,
    string Status,
    DateTimeOffset FirstSeenAt,
    DateTimeOffset LastSeenAt,
    DateTimeOffset? LastHeartbeatAt,
    int RiskScore,
    string RiskReason);

public sealed record MobileDeviceRegistration(
    string DeviceId,
    string DisplayName,
    string Platform,
    string Manufacturer,
    string Model,
    string OsVersion,
    string AppVersion,
    string TokenHash);

public sealed record MobileEnrollmentRequest(
    string PairingCode,
    string DeviceId,
    string DisplayName,
    string Platform,
    string Manufacturer,
    string Model,
    string OsVersion,
    string AppVersion);

public sealed record MobileEnrollmentResultDto(
    bool Ok,
    string DeviceId,
    string DeviceToken,
    string Message);

public sealed record MobileHeartbeatRequest(
    string DeviceToken,
    string DeviceId,
    int BatteryPercent,
    bool Charging,
    long StorageFreeMb,
    bool ScreenLockEnabled,
    bool DeveloperModeEnabled,
    bool UsbDebuggingEnabled,
    bool UnknownSourcesEnabled,
    bool VpnActive,
    DateTimeOffset ObservedAt);

public sealed record MobileAppInventoryItemDto(
    string PackageName,
    string AppName,
    string VersionName,
    long VersionCode,
    string InstallerPackage,
    bool SystemApp,
    bool Sideloaded,
    IReadOnlyList<string> RequestedPermissions,
    DateTimeOffset FirstInstallTime,
    DateTimeOffset LastUpdateTime,
    string Sha256);

public sealed record MobileAppInventoryRequest(
    string DeviceToken,
    string DeviceId,
    DateTimeOffset ObservedAt,
    IReadOnlyList<MobileAppInventoryItemDto> Apps);

public sealed record MobileSecurityFindingDto(
    string FindingId,
    DateTimeOffset ObservedAt,
    string Severity,
    int RiskScore,
    string Category,
    string Title,
    string Detail,
    string EntityType,
    string EntityId,
    string Status);

public sealed record MobileFindingsRequest(
    string DeviceToken,
    string DeviceId,
    DateTimeOffset ObservedAt,
    IReadOnlyList<MobileSecurityFindingDto> Findings);

public sealed record MobileNetworkEventDto(
    string EventId,
    string DeviceId,
    DateTimeOffset ObservedAt,
    string Protocol,
    string DestinationHost,
    string DestinationIp,
    int DestinationPort,
    string AppPackage,
    string Verdict,
    int RiskScore);

public sealed record MobilePolicyDto(
    bool RequireVpn,
    bool AlertOnSideloadedApps,
    bool AlertOnDeveloperMode,
    int RiskyPermissionThreshold,
    IReadOnlyList<string> BlockedPackages);

public sealed record MobileDashboardViewDto(
    DateTimeOffset GeneratedAt,
    IReadOnlyList<MobileDeviceDto> Devices,
    IReadOnlyList<MobileAppInventoryItemDto> RecentApps,
    IReadOnlyList<MobileSecurityFindingDto> Findings,
    IReadOnlyList<MobileNetworkEventDto> NetworkEvents,
    MobilePolicyDto Policy);

public sealed record AppActivityObservationDto(
    string AppId,
    string Name,
    string Publisher,
    string Version,
    string InstallLocation,
    bool IsCurrentlyRunning,
    int CurrentProcessCount,
    int CurrentNetworkConnectionCount,
    bool AutoStart,
    DateTimeOffset ObservedAt);

public sealed record AppActivityDto(
    string AppId,
    string Name,
    string Publisher,
    string Version,
    string InstallLocation,
    DateTimeOffset FirstSeenAt,
    DateTimeOffset LastSeenInstalledAt,
    DateTimeOffset? LastSeenRunningAt,
    DateTimeOffset? LastNetworkActivityAt,
    int ObservedRunCount,
    int ObservedNetworkCount,
    bool IsCurrentlyRunning,
    int CurrentProcessCount,
    int CurrentNetworkConnectionCount,
    bool AutoStart,
    int? DaysSinceLastUse,
    string Recommendation,
    int RiskScore,
    string RiskReason);

public sealed record AppActivityDashboardDto(
    DateTimeOffset GeneratedAt,
    int InstalledAppCount,
    int ActiveAppCount,
    int UnusedAppCount,
    int UnusedButActiveCount,
    IReadOnlyList<AppActivityDto> Apps);

public sealed record MalwareDetectionDto(
    string DetectionId,
    DateTimeOffset DetectedAt,
    string ThreatName,
    string Severity,
    string Action,
    string Resource,
    string Status,
    string Source);

public sealed record MalwareFileObservationDto(
    string Path,
    string Sha256,
    string SourceType,
    string SourceName,
    string Reputation,
    int RiskScore,
    string Reason);

public sealed record MalwareScanCapabilityDto(
    string Name,
    string Status,
    string Detail);

public sealed record MalwareGuardDashboardDto(
    DateTimeOffset GeneratedAt,
    DefenderStatusDto Defender,
    IReadOnlyList<MalwareDetectionDto> RecentDetections,
    IReadOnlyList<MalwareFileObservationDto> SuspiciousFiles,
    IReadOnlyList<MalwareScanCapabilityDto> Capabilities);

public sealed record DriverInventoryTelemetry(
    string Name,
    string DisplayName,
    string State,
    string StartMode,
    string Path,
    string ServiceType);

public sealed record InstalledSoftwareTelemetry(
    string Name,
    string Version,
    string Publisher,
    string InstallLocation,
    string RegistrySource);

public sealed record RegistryPersistenceTelemetry(
    string Hive,
    string Key,
    string Name,
    string Value);

public sealed record FileInventoryTelemetry(
    string Path,
    long Length,
    DateTimeOffset LastWriteTime,
    string Extension);

public sealed record PowerShellSecurityTelemetry(
    string ExecutionPolicy,
    bool ScriptBlockLogging,
    bool ModuleLogging,
    bool Transcription,
    string Version);

public sealed record LocalNetworkListenerTelemetry(
    string Protocol,
    string LocalAddress,
    int LocalPort,
    int ProcessId,
    string ProcessName,
    string ProcessPath);

public sealed record DeviceIntegritySnapshot(
    DateTimeOffset ObservedAt,
    IReadOnlyList<DriverInventoryTelemetry> Drivers,
    IReadOnlyList<InstalledSoftwareTelemetry> InstalledSoftware,
    IReadOnlyList<RegistryPersistenceTelemetry> RegistryPersistence,
    IReadOnlyList<FileInventoryTelemetry> MonitoredFiles,
    IReadOnlyList<ServiceTelemetry> Services,
    IReadOnlyList<ScheduledTaskTelemetry> ScheduledTasks,
    IReadOnlyList<FirewallProfileTelemetry> FirewallProfiles,
    IReadOnlyList<LocalNetworkListenerTelemetry> NetworkListeners,
    PowerShellSecurityTelemetry PowerShell,
    IReadOnlyList<string> CollectionErrors);

public sealed record DeviceIntegrityChangeEvent(
    string EventId,
    DateTimeOffset ObservedAt,
    string EntityType,
    string EntityKey,
    string ChangeType,
    string BeforeJson,
    string AfterJson,
    string Explanation);

public sealed record DeviceIntegrityFindingDto(
    string FindingId,
    DateTimeOffset ObservedAt,
    string Severity,
    int RiskScore,
    string EntityType,
    string EntityKey,
    string ChangeType,
    string Title,
    string Explanation,
    string Status,
    string ResolutionNote,
    DateTimeOffset? ResolvedAt,
    string ResolvedBy);

public sealed record DeviceIntegrityFindingStatusRequest(
    string Status,
    string Note);

public sealed record ConnectionTelemetry(
    string Protocol,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort,
    string State,
    int ProcessId,
    string ProcessName,
    string ProcessPath);

public sealed record ProcessTelemetry(
    int ProcessId,
    string Name,
    string Path,
    double MemoryMb,
    double PrivateMemoryMb,
    double CpuPercent,
    int HandleCount,
    int ThreadCount,
    int ConnectionCount,
    DateTimeOffset? StartedAt,
    int ParentProcessId = 0,
    string ParentProcessName = "",
    string CommandLine = "");

public sealed record ProcessMetadataTelemetry(
    int ProcessId,
    int ParentProcessId,
    string CommandLine);

public sealed record StartupTelemetry(string Name, string Command, string Source);

public sealed record ScheduledTaskTelemetry(
    string Name,
    string Path,
    string State,
    bool Enabled,
    string Author,
    string Command,
    string Arguments,
    string Trigger);

public sealed record ServiceTelemetry(
    string Name,
    string DisplayName,
    string State,
    string StartMode,
    string Path,
    int ProcessId,
    string Account);

public sealed record FirewallProfileTelemetry(
    string Name,
    bool Enabled,
    string DefaultInboundAction,
    string DefaultOutboundAction,
    bool NotificationsDisabled);

public sealed record FirewallStatusDto(
    bool Available,
    bool AnyProfileEnabled,
    IReadOnlyList<FirewallProfileTelemetry> Profiles,
    string Message);

public sealed record AgentInstallationTelemetry(
    string Name,
    string Path,
    string Version,
    string Publisher,
    string Source,
    bool IsRunning,
    int? ProcessId);

public sealed record SuspiciousPathTelemetry(
    string Path,
    string SourceType,
    string SourceName,
    string Reason);

public sealed record Risk(int Score, string Reason);
public sealed record CpuSample(TimeSpan TotalProcessorTime, DateTimeOffset Timestamp);
public sealed record CommandResult(int ExitCode, string Output, string Error);
public sealed record AgentEvaluation(
    bool IsAgent,
    bool NetworkAuthorized,
    bool ExplicitlyBlocked,
    string AgentName = "",
    string Vendor = "",
    string Status = "unknown",
    int RiskScore = 0,
    string RiskReason = "");

public sealed record AgentDefinitionDto(
    string AgentKey,
    string Name,
    string Vendor,
    IReadOnlyList<string> IdentityMarkers,
    IReadOnlyList<string> TrustedPathMarkers,
    bool SharedHost);

public sealed record AgentIdentityDto(
    bool IsAgent,
    string AgentKey,
    string Name,
    string Vendor,
    bool TrustedPath,
    bool SharedHost);

public sealed record AgentGovernanceDto(
    string AgentKey,
    string Name,
    string ExecutablePath,
    string Vendor,
    string Status,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen,
    bool IsRunning,
    int? ProcessId,
    int NetworkConnectionCount,
    int DistinctRemoteAddressCount,
    DateTimeOffset? NetworkLastSeen,
    int RiskScore,
    string RiskReason,
    bool NetworkAuthorized,
    bool CanEnforcePath);

public sealed record SummaryDto(
    string MachineName,
    string Os,
    bool IsAdministrator,
    DateTimeOffset GeneratedAt,
    int ConnectionCount,
    int ProcessCount,
    int StartupEntryCount,
    DefenderStatusDto Defender,
    int HighAlerts,
    int MediumAlerts,
    int LowAlerts,
    int CriticalAlerts = 0,
    int InfoAlerts = 0);

public sealed record ConnectionDto(
    string Protocol,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort,
    string State,
    int ProcessId,
    string ProcessName,
    string ProcessPath,
    int RiskScore,
    string RiskReason);

public sealed record ProcessDto(
    int ProcessId,
    string Name,
    string Path,
    double MemoryMb,
    double PrivateMemoryMb,
    double CpuPercent,
    int HandleCount,
    int ThreadCount,
    int ConnectionCount,
    DateTimeOffset? StartedAt,
    int RiskScore,
    string RiskReason,
    bool IsAgent,
    bool NetworkAuthorized);

public sealed record MemoryDto(double TotalGb, double UsedGb, double AvailableGb, uint UsedPercent);

public sealed record PerformanceDto(
    DateTimeOffset GeneratedAt,
    MemoryDto Memory,
    int ProcessCount,
    int HeavyMemoryProcessCount,
    int HeavyCpuProcessCount,
    IEnumerable<ProcessDto> TopMemoryProcesses,
    IEnumerable<ProcessDto> TopCpuProcesses);

public sealed record StartupEntryDto(string Name, string Command, string Source, int RiskScore);

public sealed record DefenderStatusDto(
    bool ServiceEnabled,
    bool AntivirusEnabled,
    bool RealTimeProtectionEnabled,
    bool NetworkInspectionEnabled,
    int? QuickScanAge,
    int? FullScanAge,
    DateTimeOffset? SignatureLastUpdated,
    string SignatureVersion,
    string Message);

public sealed record AlertDto(
    string Id,
    DateTimeOffset Timestamp,
    string Category,
    string Severity,
    string Title,
    string Detail);

public sealed record MitreMappingDto(
    string Tactic,
    string TechniqueId,
    string TechniqueName,
    string? SubtechniqueId,
    string MappingType = "Direct");

public sealed record MitreTechniqueDto(
    string TechniqueId,
    string Name,
    string PrimaryTactic,
    string Status,
    string? ReplacedBy,
    string Url);

public sealed record MitreEventDto(
    string FindingId,
    string RuleId,
    string Tactic,
    string TechniqueId,
    string TechniqueName,
    string MappingType,
    string Severity,
    string Host,
    DateTimeOffset FirstSeenAt,
    DateTimeOffset LastSeenAt,
    int OccurrenceCount,
    string Category,
    string Title,
    string Evidence,
    string EntityType,
    string EntityId);

public sealed record DetectionRuleDto(
    string RuleId,
    string Name,
    string Description,
    string Category,
    bool Enabled,
    string Severity,
    int RiskWeight,
    int Confidence,
    string ConfigurationJson,
    IReadOnlyList<MitreMappingDto> MitreMappings);

public sealed record DetectionFindingDto(
    string FindingId,
    DateTimeOffset ObservedAt,
    string RuleId,
    string RuleName,
    string Category,
    string Severity,
    int RiskScore,
    string Title,
    string Description,
    string Evidence,
    string EntityType,
    string EntityId,
    IReadOnlyList<MitreMappingDto> MitreMappings);

public sealed record DetectionResultDto(
    DateTimeOffset ObservedAt,
    int OverallRiskScore,
    string OverallSeverity,
    IReadOnlyList<DetectionFindingDto> Findings);

public sealed record RuleEnabledRequest(bool Enabled);
public sealed record SettingChangeRequest(string Value);
public sealed record SystemSettingDto(
    string Key,
    string Value,
    string ValueType,
    DateTimeOffset UpdatedAt);

public sealed record IpBlockDto(string IpAddress, string DisplayName, DateTimeOffset BlockedAt);
public sealed record PolicyRuleDto(string Name, string Detail);

public sealed record PolicyReviewDto(
    IEnumerable<string> AuthorizedAgentPaths,
    IEnumerable<string> BlockedAgentPaths,
    IEnumerable<IpBlockDto> BlockedIps,
    IEnumerable<PolicyRuleDto> ActivePolicies);

public sealed record ActionResultDto(bool Ok, string Output, string Error);
public sealed record ScanRequest(string Type);
public sealed record BlockIpRequest(string IpAddress);
public sealed record UnblockIpRequest(string IpAddress);
public sealed record KillProcessRequest(int ProcessId);
public sealed record AgentPolicyRequest(string Path);
public sealed record QuarantineFileRequest(string Path);
public sealed record DisableStartupRequest(
    string Name,
    string Source,
    string Command);
public sealed record AlertDispositionRequest(string AlertId, string Note);
public sealed record LoginRequest(string Token);
public sealed record SessionDto(
    bool Authenticated,
    string Role,
    string CsrfToken,
    DateTimeOffset? ExpiresAt);
public sealed record LocalSession(
    string SessionId,
    string Role,
    string CsrfToken,
    DateTimeOffset ExpiresAt);
public sealed record PowerShellCommand(
    string Script,
    IReadOnlyDictionary<string, string>? Parameters = null);
public sealed record AlertStateDto(
    string AlertId,
    string Status,
    string ResolutionNote,
    DateTimeOffset? ResolvedAt,
    string ResolvedBy);
public sealed record DisabledStartupItemRecord(
    string DisableId,
    string SourceType,
    string Source,
    string ItemName,
    string OriginalValue,
    string BackupPath,
    DateTimeOffset DisabledAt,
    string DisabledBy);

public sealed record AgentViewDto(
    IEnumerable<string> AuthorizedPaths,
    IEnumerable<string> BlockedPaths,
    IEnumerable<AgentGovernanceDto> Agents);

public sealed record SecurityOverviewViewDto(
    SummaryDto Summary,
    PerformanceDto Performance,
    FirewallStatusDto Firewall,
    DetectionResultDto Detection,
    int GovernedAgentCount,
    DatabaseStatusDto Database);

public sealed record MitreDashboardViewDto(
    DateTimeOffset GeneratedAt,
    IReadOnlyList<MitreEventDto> Events,
    IReadOnlyList<MitreTechniqueDto> Techniques);

public sealed record ThreatIntelDashboardViewDto(
    IReadOnlyList<ThreatIntelProviderStatusDto> Providers,
    IReadOnlyList<ThreatIndicatorDto> Indicators);

public sealed record DashboardSettingsViewDto(
    string ProductName,
    string ProductVersion,
    string BindUrl,
    int RefreshIntervalMilliseconds,
    int TelemetryCollectionIntervalSeconds,
    int TelemetryRetentionDays,
    int AgentObservationIntervalSeconds,
    int HighSeverityScore,
    int MediumSeverityScore,
    int MemoryWarningPercent,
    int MemoryDangerPercent,
    bool ResponseAuthorizationConfigured,
    int ResponseCommandTimeoutSeconds,
    IReadOnlyList<DetectionRuleDto> DetectionRules,
    PolicyReviewDto Policies,
    DatabaseStatusDto Database);

public sealed record SchedulerTaskStatusDto(
    string TaskKey,
    string DisplayName,
    bool Enabled,
    int IntervalSeconds,
    DateTimeOffset? LastStartedAt,
    DateTimeOffset? LastCompletedAt,
    DateTimeOffset? NextRunAt,
    bool LastSuccess,
    string LastStatus,
    string LastMessage,
    int SuccessCount,
    int FailureCount);

public sealed record SchedulerDashboardDto(
    bool Enabled,
    DateTimeOffset GeneratedAt,
    IReadOnlyList<SchedulerTaskStatusDto> Tasks);

public sealed record SchedulerTaskExperienceDto(
    string TaskKey,
    string DisplayName,
    string ModuleId,
    string Workspace,
    string Category,
    string DueState,
    bool Enabled,
    int IntervalSeconds,
    DateTimeOffset? LastStartedAt,
    DateTimeOffset? LastCompletedAt,
    DateTimeOffset? NextRunAt,
    bool LastSuccess,
    string LastStatus,
    string LastMessage,
    int SuccessCount,
    int FailureCount);

public sealed record SchedulerExperienceDashboardDto(
    bool Enabled,
    DateTimeOffset GeneratedAt,
    string Health,
    int RunningCount,
    int FailedCount,
    int DueCount,
    int DisabledCount,
    IReadOnlyList<SchedulerTaskExperienceDto> Tasks);

public sealed record BackupExportDto(
    string FileName,
    string ContentType,
    byte[] Content);

public sealed record BackupRestoreDto(
    bool Ok,
    string Message,
    string Sha256,
    string BackupPath);

public sealed record AgentPolicy(HashSet<string> AuthorizedPaths, HashSet<string> BlockedPaths)
{
    public AgentPolicy()
        : this(
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase))
    {
    }

    public AgentPolicy(IEnumerable<string> authorizedPaths, IEnumerable<string> blockedPaths)
        : this(
            new HashSet<string>(
                authorizedPaths.Where(path => !string.IsNullOrWhiteSpace(path)),
                StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(
                blockedPaths.Where(path => !string.IsNullOrWhiteSpace(path)),
                StringComparer.OrdinalIgnoreCase))
    {
    }
}

public sealed record ThreatIntelObservationDto(
    string Provider,
    bool HasIntelligence,
    int Confidence,
    string Reputation,
    string Summary,
    string ReferenceUrl,
    DateTimeOffset ObservedAt,
    DateTimeOffset? ExpiresAt,
    bool FromCache = false);

public sealed record ThreatIntelResult(
    string Indicator,
    string IndicatorType,
    bool HasIntelligence,
    int Confidence,
    string Reputation,
    bool FromCache,
    IReadOnlyList<ThreatIntelObservationDto> Observations,
    DateTimeOffset? ExpiresAt);

public sealed record ThreatIndicatorDto(
    string Indicator,
    string IndicatorType,
    string Reputation,
    int Confidence,
    string Source,
    DateTimeOffset FirstSeenAt,
    DateTimeOffset LastSeenAt,
    DateTimeOffset? ExpiresAt,
    string Description,
    IReadOnlyList<string> Tags,
    string MetadataJson);

public sealed record LocalIocRequest(
    string Indicator,
    string IndicatorType,
    string Reputation,
    int Confidence,
    string Description,
    string[] Tags,
    DateTimeOffset? ExpiresAt);

public sealed record ThreatIntelQueryRequest(
    string Indicator,
    string IndicatorType);

public sealed record ThreatIntelProviderStatusDto(
    string Name,
    bool Enabled,
    bool Configured,
    IReadOnlyList<string> SupportedIndicatorTypes);

public sealed record AuditLogEntryDto(
    string AuditId,
    DateTimeOffset OccurredAt,
    string Actor,
    string Action,
    string EntityType,
    string EntityId,
    bool Success,
    string DetailJson);

public sealed record ResponseActionRecord(
    string ActionId,
    DateTimeOffset RequestedAt,
    DateTimeOffset CompletedAt,
    string ActionType,
    string Target,
    string Status,
    bool Success,
    string Output,
    string Error,
    string RequestedBy,
    string BeforeJson = "{}",
    string AfterJson = "{}");

public sealed record DatabaseStatusDto(
    string Provider,
    long LatestMigration,
    int AppliedMigrationCount,
    IReadOnlyDictionary<string, long> TableRowCounts);

public sealed record SecuritySnapshot(
    IReadOnlyList<ConnectionDto> Connections,
    IReadOnlyList<ProcessDto> Processes,
    IReadOnlyList<StartupEntryDto> StartupEntries,
    DefenderStatusDto Defender,
    TelemetrySnapshot Raw,
    DetectionResultDto Detection);

public sealed record TelemetrySnapshot(
    DateTimeOffset ObservedAt,
    IReadOnlyList<ConnectionTelemetry> Connections,
    IReadOnlyList<ProcessTelemetry> Processes,
    IReadOnlyList<StartupTelemetry> StartupEntries,
    IReadOnlyList<ScheduledTaskTelemetry> ScheduledTasks,
    IReadOnlyList<ServiceTelemetry> Services,
    DefenderStatusDto Defender,
    FirewallStatusDto Firewall,
    IReadOnlyList<AgentInstallationTelemetry> InstalledAgents,
    IReadOnlyList<SuspiciousPathTelemetry> SuspiciousPaths,
    IReadOnlyList<AgentGovernanceDto>? GovernedAgents = null);

public sealed record AgentEgressRuleDto(
    string RuleId,
    string AgentKey,
    string ExecutablePath,
    string DisplayName,
    string Direction,
    string Action,
    DateTimeOffset CreatedAt,
    string CreatedBy);

public sealed record AgentEgressRuleRequest(
    string Path,
    string? AgentKey = null);

public sealed record CodeGateActiveRuleDto(
    string RuleId,
    string BundleId,
    string Name,
    string Severity,
    int RiskScore,
    string Pattern,
    string Explanation,
    bool Enabled);

public sealed record McpToolCallEventDto(
    string EventId,
    DateTimeOffset Timestamp,
    string AgentKey,
    string ServerName,
    string ToolName,
    string ArgumentsJson,
    string ResultSummary,
    int RiskScore,
    string Severity,
    string Verdict,
    string PolicyReason,
    int? ProcessId = null,
    string ClientHost = "127.0.0.1");

public sealed record McpToolCallRequest(
    string AgentKey,
    string ServerName,
    string ToolName,
    string ArgumentsJson,
    string? ResultSummary = null,
    int? ProcessId = null);

public sealed record McpAuditSummaryDto(
    DateTimeOffset GeneratedAt,
    int TotalCount,
    int BlockedCount,
    int WarnedCount,
    IReadOnlyList<string> DistinctServers,
    IReadOnlyList<string> DistinctTools,
    IReadOnlyList<McpToolCallEventDto> RecentEvents);

public sealed record DevHubNodeInfoDto(
    string NodeId,
    string Role,
    string Owner,
    string TzOffset);

public sealed record DevHubSyncRepoResultDto(
    string Name,
    string Status,
    string? Message = null,
    int? ExitCode = null);

public sealed record DevHubSyncStatusDto(
    DateTimeOffset? LastPushAt,
    bool PushHealthy,
    IReadOnlyList<DevHubSyncRepoResultDto> PushResults,
    DateTimeOffset? LastPullAt,
    bool PullHealthy,
    int TotalManagedRepos);

public sealed record DevHubClaimDto(
    string Id,
    string App,
    string Agent,
    string Task,
    IReadOnlyList<string> Scope,
    string Status,
    string Branch,
    string Base,
    string Worktree,
    DateTimeOffset Created,
    DateTimeOffset LeaseUntil,
    string? Cycle = null,
    string? Notes = null);

public sealed record DevHubCycleDto(
    string Id,
    string Name,
    IReadOnlyList<string> Goals,
    DateTimeOffset Start,
    string PlannedEnd,
    string Branch,
    string StartVersion,
    bool Closed);

public sealed record DevHubSummaryDto(
    DateTimeOffset GeneratedAt,
    DevHubNodeInfoDto Node,
    DevHubSyncStatusDto Sync,
    IReadOnlyList<DevHubClaimDto> ActiveClaims,
    IReadOnlyList<DevHubCycleDto> Cycles,
    IReadOnlyList<string> RecentReports);



