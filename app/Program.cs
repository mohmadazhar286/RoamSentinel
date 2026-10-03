using RoamSentinel.AgentGovernance;
using RoamSentinel.AppActivity;
using RoamSentinel.App;
using RoamSentinel.App.Api;
using RoamSentinel.App.DevOps;
using RoamSentinel.App.Infrastructure;
using RoamSentinel.App.Modules;
using RoamSentinel.App.Queries;
using RoamSentinel.App.Security;
using RoamSentinel.Config;
using RoamSentinel.Core;
using RoamSentinel.Dashboard;
using RoamSentinel.Database;
using RoamSentinel.Database.Migrations;
using RoamSentinel.Detection;
using RoamSentinel.DeviceShield;
using RoamSentinel.CodeGate;
using RoamSentinel.InsiderRisk;
using RoamSentinel.Logs;
using RoamSentinel.MalwareGuard;
using RoamSentinel.MobileBridge;
using RoamSentinel.Response;
using RoamSentinel.Telemetry;
using RoamSentinel.ThreatIntel;

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    WebRootPath = "public"
});
builder.Host.UseWindowsService(options =>
{
    options.ServiceName = "RoamSentinel";
});

var runtimePaths = new RuntimePathService(AppContext.BaseDirectory);
runtimePaths.EnsureDirectories();
builder.Configuration.AddJsonFile(
    Path.Combine(runtimePaths.Paths.ConfigDirectory, "appsettings.json"),
    optional: true,
    reloadOnChange: true);
var options = PlatformConfiguration.Load(builder.Configuration);

builder.WebHost.UseUrls(options.Host.BindUrl);

builder.Services.AddSingleton(options.Host);
builder.Services.AddSingleton(options.Database);
builder.Services.AddSingleton(options.Telemetry);
builder.Services.AddSingleton(options.Detection);
builder.Services.AddSingleton(options.Response);
builder.Services.AddSingleton(options.AgentGovernance);
builder.Services.AddSingleton(options.AccessControl);
builder.Services.AddSingleton(options.StructuredLogging);
builder.Services.AddSingleton(options.ThreatIntel);
builder.Services.AddSingleton(options.Dashboard);
builder.Services.AddSingleton(options.Scheduler);
builder.Services.AddSingleton<IProductModule, DeviceShieldModule>();
builder.Services.AddSingleton<IProductModule, DataEgressModule>();
builder.Services.AddSingleton<IProductModule, ProtectionSchedulerModule>();
builder.Services.AddSingleton<IProductModule, CodeGateModule>();
builder.Services.AddSingleton<IProductModule, InsiderRiskModule>();
builder.Services.AddSingleton<IProductModule, MobileBridgeModule>();
builder.Services.AddSingleton<IProductModule, AppActivityModule>();
builder.Services.AddSingleton<IProductModule, MalwareGuardModule>();
builder.Services.AddSingleton<IModuleExperienceService, ModuleExperienceService>();
builder.Services.AddSingleton<ICodeGateService, CodeGateService>();
builder.Services.AddSingleton<
    IPersonalProtectionProfileService,
    PersonalProtectionProfileService>();
builder.Services.AddSingleton<
    IProtectionSchedulerExperienceService,
    ProtectionSchedulerExperienceService>();
builder.Services.AddSingleton<IInsiderRiskService, InsiderRiskService>();
builder.Services.AddSingleton<IRuntimePathService>(runtimePaths);
builder.Services.AddSingleton<ILocalSecretStore, DpapiSecretStore>();
builder.Services.AddSingleton<IDatabaseConnectionFactory, SqliteConnectionFactory>();
builder.Services.AddSingleton<IDatabaseMigration, InitialSchemaMigration>();
builder.Services.AddSingleton<IDatabaseMigration, NormalizedTelemetryMigration>();
builder.Services.AddSingleton<IDatabaseMigration, UnifiedDetectionMigration>();
builder.Services.AddSingleton<IDatabaseMigration, LegacyDetectionMappingCleanupMigration>();
builder.Services.AddSingleton<IDatabaseMigration, MitreCoverageMigration>();
builder.Services.AddSingleton<IDatabaseMigration, ThreatIntelligenceMigration>();
builder.Services.AddSingleton<IDatabaseMigration, ResponseControlMigration>();
builder.Services.AddSingleton<IDatabaseMigration, AgentGovernanceMigration>();
builder.Services.AddSingleton<IDatabaseMigration, AgentCatalogSafetyMigration>();
builder.Services.AddSingleton<IDatabaseMigration, DeviceIntegrityMigration>();
builder.Services.AddSingleton<IDatabaseMigration, MobileBridgeMigration>();
builder.Services.AddSingleton<IDatabaseMigration, AppActivityMalwareGuardMigration>();
builder.Services.AddSingleton<IDatabaseMigration, ProtectionFindingsCodeGateMigration>();
builder.Services.AddSingleton<IDatabaseMigration, CodeGateGitTraceabilityMigration>();
builder.Services.AddSingleton<IDatabaseMigration, CodeGateOfflineBundleMigration>();
builder.Services.AddSingleton<IDatabaseMigration, ProtectionSchedulerMigration>();
builder.Services.AddSingleton<IDatabaseMigration, AgentGovernanceExpansionMigration>();
builder.Services.AddSingleton<IDatabaseMigration, McpGovernanceMigration>();
builder.Services.AddSingleton<IDatabaseMigrationRunner, DatabaseMigrationRunner>();
builder.Services.AddSingleton<ILegacyDataImporter, LegacyDataImporter>();
builder.Services.AddSingleton<IEventRepository, EventRepository>();
builder.Services.AddSingleton<IAgentPolicyRepository, AgentPolicyRepository>();
builder.Services.AddSingleton<IAgentRegistryRepository, AgentRegistryRepository>();
builder.Services.AddSingleton<IAgentEgressRuleRepository, AgentEgressRuleRepository>();
builder.Services.AddSingleton<IMcpTelemetryRepository, McpTelemetryRepository>();
builder.Services.AddSingleton<IIpBlockRepository, IpBlockRepository>();
builder.Services.AddSingleton<IAuditRepository, AuditRepository>();
builder.Services.AddSingleton<IResponseActionRepository, ResponseActionRepository>();
builder.Services.AddSingleton<IDisabledStartupRepository, DisabledStartupRepository>();
builder.Services.AddSingleton<ITelemetryRepository, TelemetryRepository>();
builder.Services.AddSingleton<
    IDeviceIntegrityRepository,
    DeviceIntegrityRepository>();
builder.Services.AddSingleton<
    IDeviceIntegrityFindingRepository,
    DeviceIntegrityFindingRepository>();
builder.Services.AddSingleton<ICodeGateRepository, CodeGateRepository>();
builder.Services.AddSingleton<
    ICodeGateGitAuditRepository,
    CodeGateGitAuditRepository>();
builder.Services.AddSingleton<ICodeGateBundleRepository, CodeGateBundleRepository>();
builder.Services.AddSingleton<ICodeGateActiveRuleRepository, CodeGateActiveRuleRepository>();
builder.Services.AddSingleton<ICodeGateBundleService, CodeGateBundleService>();
builder.Services.AddSingleton<IDetectionRuleRepository, DetectionRuleRepository>();
builder.Services.AddSingleton<IThreatIndicatorRepository, ThreatIndicatorRepository>();
builder.Services.AddSingleton<IMitreRepository, MitreRepository>();
builder.Services.AddSingleton<IDatabaseStatusRepository, DatabaseStatusRepository>();
builder.Services.AddSingleton<IMobileDeviceRepository, MobileDeviceRepository>();
builder.Services.AddSingleton<IAppActivityRepository, AppActivityRepository>();
builder.Services.AddSingleton<IMalwareGuardRepository, MalwareGuardRepository>();
builder.Services.AddSingleton<ISystemSettingsRepository, SystemSettingsRepository>();
builder.Services.AddSingleton<
    IProtectionSchedulerRepository,
    ProtectionSchedulerRepository>();
builder.Services.AddSingleton<IDevHubStatusService, DevHubStatusService>();
builder.Services.AddSingleton<IBackupExportService, BackupExportService>();
builder.Services.AddSingleton<IEventLogService, EventLogService>();
builder.Services.AddSingleton<IStructuredLogService>(services =>
    new StructuredLogService(
        services.GetRequiredService<IRuntimePathService>(),
        services.GetRequiredService<StructuredLoggingOptions>()));
builder.Services.AddSingleton<ILocalSessionService, LocalSessionService>();
builder.Services.AddSingleton<IPrivilegeService, WindowsPrivilegeService>();
builder.Services.AddHttpClient("ThreatIntel", client =>
{
    client.Timeout = TimeSpan.FromSeconds(
        options.ThreatIntel.RequestTimeoutSeconds);
});
builder.Services.AddHttpClient("Misp", client =>
{
    client.Timeout = TimeSpan.FromSeconds(
        options.ThreatIntel.RequestTimeoutSeconds);
}).ConfigurePrimaryHttpMessageHandler(() =>
{
    var handler = new HttpClientHandler();
    if (!options.ThreatIntel.Misp.VerifyTls)
    {
        handler.ServerCertificateCustomValidationCallback =
            HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
    }

    return handler;
});
builder.Services.AddSingleton<IPowerShellRunner, PowerShellRunner>();
builder.Services.AddSingleton<ProcessTelemetryCollector>();
builder.Services.AddSingleton<StartupTelemetryCollector>();
builder.Services.AddSingleton<AgentInstallationCollector>();
builder.Services.AddSingleton<ITelemetryService, WindowsTelemetryService>();
builder.Services.AddSingleton<
    IDeviceIntegrityInventoryService,
    DeviceIntegrityInventoryService>();
builder.Services.AddHostedService<DeviceIntegrityMonitorService>();
builder.Services.AddHostedService<ProtectionSchedulerService>();
builder.Services.AddSingleton<IResourceMonitor, ResourceMonitor>();
builder.Services.AddSingleton<IDetectionEngine, DetectionEngine>();
builder.Services.AddSingleton<IAgentGovernanceService, AgentGovernanceService>();
builder.Services.AddSingleton<IMcpGovernanceService, McpGovernanceService>();
builder.Services.AddSingleton<IAgentIdentityService, AgentIdentityService>();
builder.Services.AddSingleton<IThreatIntelProvider, VirusTotalProvider>();
builder.Services.AddSingleton<IThreatIntelProvider, AbuseIpDbProvider>();
builder.Services.AddSingleton<IThreatIntelProvider, AlienVaultOtxProvider>();
builder.Services.AddSingleton<IThreatIntelProvider, MispProvider>();
builder.Services.AddSingleton<IThreatIntelService, ThreatIntelService>();
builder.Services.AddSingleton<IMobileBridgeService, MobileBridgeService>();
builder.Services.AddSingleton<IAppActivityService, AppActivityService>();
builder.Services.AddSingleton<IMalwareGuardService, MalwareGuardService>();
builder.Services.AddSingleton<IResponseService, ResponseService>();
builder.Services.AddSingleton<ISecuritySnapshotService, SecuritySnapshotService>();
builder.Services.AddSingleton<IDashboardQueryService, DashboardQueryService>();

var app = builder.Build();

app.Services.GetRequiredService<IDatabaseMigrationRunner>().Migrate();
app.Services.GetRequiredService<ILegacyDataImporter>().Import();

var exportBackupIndex = Array.FindIndex(
    args,
    argument => string.Equals(
        argument,
        "--export-backup",
        StringComparison.OrdinalIgnoreCase));
if (exportBackupIndex >= 0)
{
    if (exportBackupIndex + 1 >= args.Length)
    {
        throw new ArgumentException("--export-backup requires an output directory.");
    }

    var outputDirectory = Path.GetFullPath(args[exportBackupIndex + 1]);
    Directory.CreateDirectory(outputDirectory);
    var export = app.Services
        .GetRequiredService<IBackupExportService>()
        .Create("local-cli");
    var outputPath = Path.Combine(outputDirectory, export.FileName);
    await File.WriteAllBytesAsync(outputPath, export.Content);
    Console.WriteLine($"Backup exported: {outputPath}");
    return;
}

var restoreIndex = Array.FindIndex(
    args,
    argument => string.Equals(
        argument,
        "--restore-backup",
        StringComparison.OrdinalIgnoreCase));
if (restoreIndex >= 0)
{
    if (restoreIndex + 1 >= args.Length)
    {
        throw new ArgumentException("--restore-backup requires a ZIP file path.");
    }

    await using var backup = File.OpenRead(Path.GetFullPath(args[restoreIndex + 1]));
    var restored = app.Services
        .GetRequiredService<IBackupExportService>()
        .Restore(backup, "local-cli");
    app.Services.GetRequiredService<IDatabaseMigrationRunner>().Migrate();
    Console.WriteLine(restored.Message);
    return;
}

var codeGateScanIndex = Array.FindIndex(
    args,
    argument => string.Equals(
        argument,
        "--codegate-scan",
        StringComparison.OrdinalIgnoreCase));
if (codeGateScanIndex >= 0)
{
    if (codeGateScanIndex + 1 >= args.Length)
    {
        throw new ArgumentException("--codegate-scan requires a file or directory path.");
    }

    var scanPath = Path.GetFullPath(args[codeGateScanIndex + 1]);
    var revision = ReadArgumentValue(args, "--revision") ?? "";
    var source = ReadArgumentValue(args, "--source") ?? "manual-cli";
    var result = app.Services.GetRequiredService<ICodeGateService>().ScanPath(
        new CodeGatePathScanRequest(scanPath, source, revision),
        Environment.UserName);
    Console.WriteLine(
        $"CodeGate verdict={result.Verdict} risk={result.RiskScore} " +
        $"files={result.FileCount} findings={result.Findings.Count} " +
        $"submission={result.SubmissionId}");
    foreach (var finding in result.Findings.Take(25))
    {
        Console.WriteLine(
            $"{finding.Severity} {finding.RuleId} {finding.FilePath}: " +
            finding.Explanation);
    }

    return;
}

var codeGateGitIndex = Array.FindIndex(
    args,
    argument => string.Equals(
        argument,
        "--codegate-git-push",
        StringComparison.OrdinalIgnoreCase));
if (codeGateGitIndex >= 0)
{
    var repositoryPath = ReadArgumentValue(args, "--repository") ??
        Directory.GetCurrentDirectory();
    var scanPath = ReadArgumentValue(args, "--scan-path") ?? repositoryPath;
    var refName = ReadArgumentValue(args, "--ref") ?? "";
    var branch = ReadArgumentValue(args, "--branch") ?? "";
    var oldRevision = ReadArgumentValue(args, "--old") ?? "";
    var newRevision = ReadArgumentValue(args, "--new") ??
        ReadArgumentValue(args, "--revision") ?? "";
    var actor = ReadArgumentValue(args, "--actor") ?? Environment.UserName;
    var files = ReadChangedFiles(
        ReadArgumentValue(args, "--changed-files-json"));
    var result = app.Services.GetRequiredService<ICodeGateService>().RecordGitPush(
        new CodeGateGitPushRequest(
            Path.GetFullPath(repositoryPath),
            ReadArgumentValue(args, "--repository-name") ?? "",
            refName,
            branch,
            oldRevision,
            newRevision,
            Path.GetFullPath(scanPath),
            files),
        actor);
    Console.WriteLine(
        $"CodeGate git-push verdict={result.Verdict} risk={result.RiskScore} " +
        $"repo={result.RepositoryName} branch={result.Branch} " +
        $"files={result.ChangedFiles.Count} audit={result.AuditId}");
    return;
}

var codeGateBundleIndex = Array.FindIndex(
    args,
    argument => string.Equals(
        argument,
        "--import-codegate-bundle",
        StringComparison.OrdinalIgnoreCase));
if (codeGateBundleIndex >= 0)
{
    if (codeGateBundleIndex + 1 >= args.Length)
    {
        throw new ArgumentException("--import-codegate-bundle requires a JSON bundle path.");
    }

    var bundle = app.Services.GetRequiredService<ICodeGateBundleService>()
        .ImportBundle(
            new CodeGateBundleImportRequest(
                Path.GetFullPath(args[codeGateBundleIndex + 1]),
                ReadArgumentValue(args, "--sha256") ?? ""),
            Environment.UserName);
    Console.WriteLine(
        $"CodeGate bundle imported type={bundle.BundleType} name={bundle.Name} " +
        $"version={bundle.Version} sha256={bundle.Sha256} status={bundle.Status}");
    return;
}

var schedulerStatusIndex = Array.FindIndex(
    args,
    argument => string.Equals(
        argument,
        "--scheduler-status",
        StringComparison.OrdinalIgnoreCase));
if (schedulerStatusIndex >= 0)
{
    var status = app.Services
        .GetRequiredService<IProtectionSchedulerExperienceService>()
        .GetDashboard();
    var outputPath = ReadArgumentValue(args, "--output");
    var json = args.Any(argument => string.Equals(
        argument,
        "--json",
        StringComparison.OrdinalIgnoreCase));
    var output = json
        ? System.Text.Json.JsonSerializer.Serialize(
            status,
            new System.Text.Json.JsonSerializerOptions
            {
                PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase,
                WriteIndented = true
            })
        : BuildSchedulerStatusText(status);
    if (string.IsNullOrWhiteSpace(outputPath))
    {
        Console.WriteLine(output);
    }
    else
    {
        var fullOutputPath = Path.GetFullPath(outputPath);
        Directory.CreateDirectory(Path.GetDirectoryName(fullOutputPath)!);
        await File.WriteAllTextAsync(fullOutputPath, output);
        Console.WriteLine($"Scheduler status exported: {fullOutputPath}");
    }

    return;
}

app.Services.GetRequiredService<IStructuredLogService>().App(
    "application.started",
    "RoamSentinel application started.",
    new
    {
        Environment.ProcessId,
        options.Host.BindUrl,
        LatestMigration = app.Services
            .GetRequiredService<IDatabaseStatusRepository>()
            .GetStatus()
            .LatestMigration
    });

app.UseMiddleware<StructuredRequestMiddleware>();
app.UseMiddleware<SecurityHeadersMiddleware>();
app.UseMiddleware<ApiSecurityMiddleware>();
app.UseDefaultFiles();
app.UseStaticFiles();

app.MapLegacyReadEndpoints();
app.MapDashboardSectionEndpoints();
app.MapAuthenticationEndpoints();
app.MapResponseEndpoints();
app.MapAgentGovernanceEndpoints();
app.MapDetectionRuleEndpoints();
app.MapThreatIntelEndpoints();
app.MapLogCommandEndpoints();
app.MapSettingsCommandEndpoints();
app.MapBackupEndpoints();
app.MapModuleEndpoints();
app.MapDeviceIntegrityEndpoints();
app.MapMobileBridgeEndpoints();
app.MapDevOpsEndpoints();
app.MapFallbackToFile("index.html");

app.Run();

static string? ReadArgumentValue(string[] args, string name)
{
    var index = Array.FindIndex(
        args,
        argument => string.Equals(
            argument,
            name,
            StringComparison.OrdinalIgnoreCase));
    return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
}

static IReadOnlyList<string> ReadChangedFiles(string? jsonPath)
{
    if (string.IsNullOrWhiteSpace(jsonPath) || !File.Exists(jsonPath))
    {
        return [];
    }

    try
    {
        return System.Text.Json.JsonSerializer.Deserialize<string[]>(
            File.ReadAllText(jsonPath)) ?? [];
    }
    catch
    {
        return [];
    }
}

static string BuildSchedulerStatusText(SchedulerExperienceDashboardDto status)
{
    var lines = new List<string>
    {
        $"Scheduler enabled={status.Enabled} health={status.Health} " +
        $"running={status.RunningCount} failed={status.FailedCount} " +
        $"due={status.DueCount} disabled={status.DisabledCount} " +
        $"generatedAt={status.GeneratedAt:O}"
    };
    lines.AddRange(status.Tasks.Select(task =>
        $"{task.TaskKey} module={task.ModuleId} state={task.DueState} " +
        $"intervalSeconds={task.IntervalSeconds} " +
        $"lastStatus={task.LastStatus} nextRunAt={task.NextRunAt:O}"));
    return string.Join(Environment.NewLine, lines);
}

public partial class Program;
