namespace RoamSentinel.Core;

public interface IRuntimePathService
{
    RuntimePaths Paths { get; }
    void EnsureDirectories();
    string ResolveDataPath(string path);
    string ResolveLogPath(string path);
    string ResolveConfigPath(string path);
}

public interface IProductModule
{
    ModuleRegistration Registration { get; }
}

public interface IModuleExperienceService
{
    ModuleExperienceManifestDto GetManifest();
}

public interface ICodeGateService
{
    CodeGateScanResult Evaluate(CodeGateScanRequest request);
    CodeGateSubmissionDto ScanPath(
        CodeGatePathScanRequest request,
        string actor);
    CodeGateGitPushAuditDto RecordGitPush(
        CodeGateGitPushRequest request,
        string actor);
    IReadOnlyList<CodeGateSubmissionDto> GetRecentSubmissions(int limit);
    CodeGateSubmissionDto? GetSubmission(string submissionId);
    IReadOnlyList<CodeGateGitPushAuditDto> GetRecentGitPushes(int limit);
    CodeGateGitPushAuditDto? GetGitPush(string auditId);
}

public interface ICodeGateRepository
{
    void SaveSubmission(CodeGateSubmissionDto submission);
    IReadOnlyList<CodeGateSubmissionDto> GetRecentSubmissions(int limit);
    CodeGateSubmissionDto? GetSubmission(string submissionId);
}

public interface ICodeGateGitAuditRepository
{
    void Save(CodeGateGitPushAuditDto audit);
    IReadOnlyList<CodeGateGitPushAuditDto> GetRecent(int limit);
    CodeGateGitPushAuditDto? Get(string auditId);
}

public interface ICodeGateBundleService
{
    CodeGateBundleDto ImportBundle(
        CodeGateBundleImportRequest request,
        string actor);
    IReadOnlyList<CodeGateBundleDto> GetRecentBundles(int limit);
}

public interface ICodeGateBundleRepository
{
    void Save(CodeGateBundleDto bundle);
    IReadOnlyList<CodeGateBundleDto> GetRecent(int limit);
}

public interface IPersonalProtectionProfileService
{
    PersonalProtectionProfileDto GetProfile();
}

public interface IInsiderRiskService
{
    InsiderRiskSummaryDto GetSummary();
}

public interface IMobileBridgeService
{
    MobileDashboardViewDto GetDashboard();
    MobilePairingSessionDto CreatePairingSession(string actor);
    MobileEnrollmentResultDto Enroll(MobileEnrollmentRequest request);
    MobileDeviceDto RecordHeartbeat(MobileHeartbeatRequest request);
    void RecordAppInventory(MobileAppInventoryRequest request);
    void RecordFindings(MobileFindingsRequest request);
}

public interface IMobileDeviceRepository
{
    MobileDashboardViewDto GetDashboard();
    MobilePairingSessionDto CreatePairingSession(
        string codeHash,
        DateTimeOffset expiresAt,
        string actor);
    MobilePairingSessionDto? FindActivePairingSession(
        string codeHash,
        DateTimeOffset now);
    void MarkPairingSessionUsed(string pairingId, string deviceId);
    MobileDeviceDto UpsertDevice(
        MobileDeviceRegistration registration,
        string actor);
    MobileDeviceDto? FindDeviceByTokenHash(string tokenHash);
    MobileDeviceDto RecordHeartbeat(
        string tokenHash,
        MobileHeartbeatRequest request);
    void ReplaceAppInventory(
        string deviceId,
        IReadOnlyCollection<MobileAppInventoryItemDto> apps,
        DateTimeOffset observedAt);
    void AddFindings(
        string deviceId,
        IReadOnlyCollection<MobileSecurityFindingDto> findings,
        DateTimeOffset observedAt);
}

public interface IAppActivityService
{
    Task<AppActivityDashboardDto> GetDashboardAsync(
        CancellationToken cancellationToken = default);
}

public interface IAppActivityRepository
{
    AppActivityDashboardDto RecordSnapshot(
        IReadOnlyCollection<AppActivityObservationDto> observations,
        DateTimeOffset observedAt);
    AppActivityDashboardDto GetDashboard(int limit = 250);
}

public interface IMalwareGuardService
{
    Task<MalwareGuardDashboardDto> GetDashboardAsync(
        CancellationToken cancellationToken = default);
}

public interface IMalwareGuardRepository
{
    void RecordDefenderDetections(
        IReadOnlyCollection<MalwareDetectionDto> detections,
        DateTimeOffset observedAt);
    MalwareGuardDashboardDto GetDashboard(
        DefenderStatusDto defender,
        IReadOnlyCollection<MalwareFileObservationDto> suspiciousFiles);
}
public interface ILocalSecretStore
{
    void Set(string name, string value);
    string? Get(string name);
    bool Delete(string name);
}

public interface IPowerShellRunner
{
    Task<CommandResult> RunAsync(
        PowerShellCommand command,
        TimeSpan timeout,
        CancellationToken cancellationToken = default);
}

public interface IStructuredLogService
{
    void App(string eventName, string message, object? data = null);
    void Security(string eventName, string message, object? data = null);
    void Response(string eventName, string message, object? data = null);
    void Error(string eventName, Exception exception, object? data = null);
}

public interface ILocalSessionService
{
    SessionDto Login(
        string token,
        System.Net.IPAddress? remoteAddress,
        HttpResponse response);
    SessionDto GetSession(HttpRequest request);
    LocalSession? Resolve(HttpRequest request);
    void Logout(HttpRequest request, HttpResponse response);
    bool HasRole(LocalSession? session, string requiredRole);
    bool ValidateCsrf(LocalSession? session, string? token);
}

public interface IPrivilegeService
{
    bool IsAdministrator();
}

public interface ITelemetryService
{
    Task<IReadOnlyList<ConnectionTelemetry>> GetConnectionsAsync(
        CancellationToken cancellationToken = default);

    IReadOnlyList<ProcessTelemetry> GetProcesses(
        IReadOnlyCollection<ConnectionTelemetry> connections);

    Task<IReadOnlyDictionary<int, ProcessMetadataTelemetry>>
        GetProcessMetadataAsync(
            CancellationToken cancellationToken = default);

    IReadOnlyList<StartupTelemetry> GetStartupEntries();

    Task<IReadOnlyList<ScheduledTaskTelemetry>> GetScheduledTasksAsync(
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ServiceTelemetry>> GetServicesAsync(
        CancellationToken cancellationToken = default);

    Task<DefenderStatusDto> GetDefenderStatusAsync(
        CancellationToken cancellationToken = default);

    Task<FirewallStatusDto> GetFirewallStatusAsync(
        CancellationToken cancellationToken = default);

    IReadOnlyList<AgentInstallationTelemetry> GetInstalledAgents(
        IReadOnlyCollection<ProcessTelemetry> processes);

    IReadOnlyList<SuspiciousPathTelemetry> GetSuspiciousPaths(
        IReadOnlyCollection<ProcessTelemetry> processes,
        IReadOnlyCollection<StartupTelemetry> startupEntries,
        IReadOnlyCollection<ScheduledTaskTelemetry> scheduledTasks,
        IReadOnlyCollection<ServiceTelemetry> services,
        IReadOnlyCollection<AgentInstallationTelemetry> agents);

    bool IsAdministrator();
}

public interface IDeviceIntegrityInventoryService
{
    Task<DeviceIntegritySnapshot> CollectAsync(
        CancellationToken cancellationToken = default);
}

public interface IDeviceIntegrityRepository
{
    IReadOnlyList<DeviceIntegrityChangeEvent> RecordSnapshot(
        DeviceIntegritySnapshot snapshot);
    IReadOnlyList<DeviceIntegrityChangeEvent> GetRecentEvents(int limit);
}

public interface IDeviceIntegrityFindingRepository
{
    IReadOnlyList<DeviceIntegrityFindingDto> RecordFromChanges(
        IReadOnlyCollection<DeviceIntegrityChangeEvent> changes);
    IReadOnlyList<DeviceIntegrityFindingDto> GetRecent(int limit);
    DeviceIntegrityFindingDto? SetStatus(
        string findingId,
        string status,
        string note,
        string actor);
}

public interface IResourceMonitor
{
    MemoryDto GetMemory();
}

public interface ISecuritySnapshotService
{
    Task<SecuritySnapshot> CollectAsync(
        CancellationToken cancellationToken = default);
}

public interface IDetectionEngine
{
    DetectionResultDto Evaluate(
        TelemetrySnapshot snapshot,
        AgentPolicy agentPolicy);

    ConnectionDto AssessConnection(
        ConnectionTelemetry connection,
        DetectionResultDto result);

    ProcessDto AssessProcess(
        ProcessTelemetry process,
        AgentEvaluation agent,
        DetectionResultDto result);

    StartupEntryDto AssessStartup(
        StartupTelemetry startup,
        DetectionResultDto result);

    IReadOnlyList<AlertDto> BuildAlerts(DetectionResultDto result);
}

public interface IDetectionRuleRepository
{
    IReadOnlyList<DetectionRuleDto> GetAll();
    DetectionRuleDto? SetEnabled(string ruleId, bool enabled);
}

public interface IThreatIndicatorRepository
{
    IReadOnlySet<string> GetActiveSuspiciousIps(DateTimeOffset asOf);
    IReadOnlyList<ThreatIndicatorDto> GetAll(int limit);
    ThreatIndicatorDto? FindActive(
        string indicator,
        string indicatorType,
        string source,
        DateTimeOffset asOf);
    ThreatIndicatorDto Upsert(ThreatIndicatorDto indicator, string actor);
    bool RemoveLocal(string indicator, string indicatorType);
}

public interface IMitreRepository
{
    bool PersistFindings(
        DetectionResultDto result,
        string host);

    IReadOnlyList<MitreTechniqueDto> GetTechniques();

    IReadOnlyList<MitreEventDto> GetEvents(int limit);
}

public interface IThreatIntelService
{
    Task<ThreatIntelResult> EnrichAsync(
        string indicator,
        string indicatorType,
        CancellationToken cancellationToken = default);

    Task<ThreatIntelResult> EnrichIpAsync(
        string indicator,
        CancellationToken cancellationToken = default);

    Task<ThreatIntelResult> EnrichDomainAsync(
        string indicator,
        CancellationToken cancellationToken = default);

    Task<ThreatIntelResult> EnrichFileHashAsync(
        string indicator,
        CancellationToken cancellationToken = default);

    IReadOnlyList<ThreatIntelProviderStatusDto> GetProviderStatus();
}

public interface IThreatIntelProvider
{
    string Name { get; }
    bool Enabled { get; }
    bool IsConfigured { get; }
    IReadOnlySet<string> SupportedIndicatorTypes { get; }

    Task<ThreatIntelObservationDto> EnrichAsync(
        string indicator,
        string indicatorType,
        CancellationToken cancellationToken = default);
}

public interface IAgentGovernanceService
{
    AgentPolicy GetPolicy();
    AgentEvaluation Evaluate(
        ProcessTelemetry process,
        IReadOnlyCollection<ConnectionTelemetry>? connections = null);
    IReadOnlyList<AgentGovernanceDto> Observe(TelemetrySnapshot snapshot);
    IReadOnlyList<AgentGovernanceDto> GetRegistry();
    AgentPolicy Authorize(string path);
    AgentPolicy Block(string path);
    AgentPolicy Unblock(string path);
}

public interface IAgentIdentityService
{
    AgentIdentityDto Identify(
        string name,
        string path,
        string commandLine = "");
}

public interface IAgentRegistryRepository
{
    IReadOnlyList<AgentDefinitionDto> GetDefinitions();
    void UpsertObservations(
        IReadOnlyCollection<AgentGovernanceDto> agents,
        DateTimeOffset observedAt);
    IReadOnlyList<AgentGovernanceDto> GetAll();
}

public interface IResponseService
{
    Task<ActionResultDto> StartDefenderScanAsync(
        string requestedType,
        CancellationToken cancellationToken = default);

    Task<ActionResultDto> BlockIpAsync(
        string ipAddress,
        CancellationToken cancellationToken = default);

    Task<ActionResultDto> UnblockIpAsync(
        string ipAddress,
        CancellationToken cancellationToken = default);

    Task<ActionResultDto> BlockAgentAsync(
        string path,
        CancellationToken cancellationToken = default);

    Task<ActionResultDto> UnblockAgentAsync(
        string path,
        CancellationToken cancellationToken = default);

    Task<ActionResultDto> QuarantineFileAsync(
        string path,
        CancellationToken cancellationToken = default);

    Task<ActionResultDto> DisableStartupItemAsync(
        DisableStartupRequest request,
        CancellationToken cancellationToken = default);

    ActionResultDto ResolveAlert(string alertId, string note);
    ActionResultDto MarkFalsePositive(string alertId, string note);
    ActionResultDto KillProcess(int processId);
}

public interface IEventLogService
{
    void RecordAlerts(IEnumerable<AlertDto> alerts);
    void RecordAction(string title, string severity, string detail);
    IReadOnlyList<AlertDto> GetRecent(int limit = 200);
    int Purge();
}

public interface IEventRepository
{
    bool TryAdd(AlertDto alert);
    void AddOrUpdate(AlertDto alert);
    IReadOnlyList<AlertDto> GetRecent(int limit);
    AlertStateDto? GetState(string alertId);
    AlertStateDto? SetDisposition(
        string alertId,
        string status,
        string note,
        string actor);
    int Purge();
}

public interface IAgentPolicyRepository
{
    AgentPolicy Load();
    AgentPolicy Save(AgentPolicy policy);
}

public interface IIpBlockRepository
{
    IReadOnlyList<IpBlockDto> Load();
    IpBlockDto? Find(string ipAddress);
    void Upsert(IpBlockDto block);
    void Remove(string ipAddress);
}

public interface IAuditRepository
{
    void Write(
        string actor,
        string action,
        string entityType,
        string entityId,
        bool success,
        string detailJson);

    IReadOnlyList<AuditLogEntryDto> GetRecent(int limit);
}

public interface IResponseActionRepository
{
    void Record(ResponseActionRecord action);
    IReadOnlyList<ResponseActionRecord> GetRecent(int limit);
}

public interface IDisabledStartupRepository
{
    void Record(DisabledStartupItemRecord item);
}

public interface ITelemetryRepository
{
    bool PersistSnapshot(TelemetrySnapshot snapshot);
}

public interface IDatabaseStatusRepository
{
    DatabaseStatusDto GetStatus();
}

public interface ISystemSettingsRepository
{
    IReadOnlyList<SystemSettingDto> GetAll();
    SystemSettingDto Set(string key, string value, string actor);
}

public interface IBackupExportService
{
    BackupExportDto Create(string actor);
    BackupRestoreDto Restore(Stream archive, string actor);
}

public interface IProtectionSchedulerRepository
{
    void EnsureTasks(IReadOnlyCollection<SchedulerTaskStatusDto> tasks);
    void MarkStarted(string taskKey, DateTimeOffset startedAt);
    void MarkCompleted(
        string taskKey,
        DateTimeOffset completedAt,
        bool success,
        string status,
        string message,
        DateTimeOffset nextRunAt);
    SchedulerDashboardDto GetDashboard(bool enabled);
}

public interface IProtectionSchedulerExperienceService
{
    SchedulerExperienceDashboardDto GetDashboard();
}

public interface IDashboardQueryService
{
    Task<SecurityOverviewViewDto> GetSecurityOverviewAsync(
        CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ProcessDto>> GetLiveProcessesAsync(
        CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ConnectionDto>> GetNetworkConnectionsAsync(
        CancellationToken cancellationToken = default);
    Task<IReadOnlyList<AlertDto>> GetAlertsAsync(
        CancellationToken cancellationToken = default);
    Task<MitreDashboardViewDto> GetMitreAsync(
        CancellationToken cancellationToken = default);
    Task<AgentViewDto> GetAgentsAsync(
        CancellationToken cancellationToken = default);
    ThreatIntelDashboardViewDto GetThreatIntel();
    IReadOnlyList<ResponseActionRecord> GetResponseHistory();
    DashboardSettingsViewDto GetSettings();
    IReadOnlyList<AuditLogEntryDto> GetAuditLog();
    SchedulerDashboardDto GetScheduler();
}
