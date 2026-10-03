using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using RoamSentinel.Core;

namespace RoamSentinel.Tests;

[Collection("Endpoint contracts")]
public sealed class EndpointContractTests : IDisposable
{
    private const string AdministratorToken = "contract-test-administrator-token";
    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        "RoamSentinel.Contract.Tests",
        Guid.NewGuid().ToString("N"));
    private readonly string? _previousProgramData;

    public EndpointContractTests()
    {
        _previousProgramData = Environment.GetEnvironmentVariable(
            RuntimePathService.ProgramDataOverride);
        Environment.SetEnvironmentVariable(
            RuntimePathService.ProgramDataOverride,
            _root);
        var config = Path.Combine(_root, "RoamSentinel", "config");
        Directory.CreateDirectory(config);
        File.WriteAllText(
            Path.Combine(config, "appsettings.json"),
            $$"""
            {
              "AccessControl": {
                "AdministratorToken": "{{AdministratorToken}}"
              },
              "Response": {
                "DryRun": true
              },
              "Database": {
                "ImportLegacyJson": false,
                "PersistTelemetrySnapshots": false
              }
            }
            """);
    }

    [Fact]
    public async Task ReadContractsRemainAvailableAndWritesRequireAuthentication()
    {
        using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var session = await client.GetAsync("/api/auth/session");
        var database = await client.GetAsync("/api/database/status");
        var modules = await client.GetAsync("/api/modules");
        var moduleExperiences = await client.GetAsync(
            "/api/v1/module-experiences");
        var scheduler = await client.GetAsync("/api/v1/scheduler");
        var insiderRisk = await client.GetAsync("/api/modules/insider-risk");
        var personalProtection = await client.GetAsync(
            "/api/v1/device-shield/personal-protection");
        var egressRules = await client.GetAsync(
            "/api/v1/agents/egress-rules");
        var codeGateRules = await client.GetAsync(
            "/api/v1/codegate/rules");
        var mcpEvents = await client.GetAsync(
            "/api/v1/agents/mcp-events");
        var mcpSummary = await client.GetAsync(
            "/api/v1/agents/mcp-summary");
        var devopsSummary = await client.GetAsync(
            "/api/v1/devops/summary");
        var unauthenticatedWrite = await client.PostAsJsonAsync(
            "/api/actions/scan",
            new ScanRequest("quick"));
        var unauthenticatedCodeGate = await client.PostAsJsonAsync(
            "/api/modules/codegate/scan",
            new CodeGateScanRequest(
                "const apiKey = \"12345678901234567890\";",
                "contract",
                "sample.js"));
        var unauthenticatedMcp = await client.PostAsJsonAsync(
            "/api/v1/agents/mcp-events",
            new McpToolCallRequest(
                "claude-code",
                "terminal",
                "execute_command",
                "{}"));

        Assert.Equal(HttpStatusCode.OK, session.StatusCode);
        Assert.Equal(HttpStatusCode.OK, database.StatusCode);
        Assert.Equal(HttpStatusCode.OK, modules.StatusCode);
        Assert.Equal(HttpStatusCode.OK, moduleExperiences.StatusCode);
        Assert.Equal(HttpStatusCode.OK, scheduler.StatusCode);
        Assert.Equal(HttpStatusCode.OK, insiderRisk.StatusCode);
        Assert.Equal(HttpStatusCode.OK, personalProtection.StatusCode);
        Assert.Equal(HttpStatusCode.OK, egressRules.StatusCode);
        Assert.Equal(HttpStatusCode.OK, codeGateRules.StatusCode);
        Assert.Equal(HttpStatusCode.OK, mcpEvents.StatusCode);
        Assert.Equal(HttpStatusCode.OK, mcpSummary.StatusCode);
        Assert.Equal(HttpStatusCode.OK, devopsSummary.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, unauthenticatedWrite.StatusCode);
        Assert.Equal(
            HttpStatusCode.Unauthorized,
            unauthenticatedCodeGate.StatusCode);
        Assert.Equal(
            HttpStatusCode.Unauthorized,
            unauthenticatedMcp.StatusCode);
    }

    [Fact]
    public async Task SchedulerExperienceEndpointMapsTasksToModules()
    {
        using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var scheduler = await client
            .GetFromJsonAsync<SchedulerExperienceDashboardDto>(
                "/api/v1/scheduler");

        Assert.NotNull(scheduler);
        Assert.NotEmpty(scheduler.Tasks);
        Assert.Contains(
            scheduler.Tasks,
            task => task.TaskKey == "telemetry-snapshot" &&
                task.ModuleId == "data-egress");
        Assert.Contains(
            scheduler.Tasks,
            task => task.TaskKey == "weekly-review" &&
                task.ModuleId == "protection-scheduler");
        Assert.All(
            scheduler.Tasks,
            task => Assert.False(string.IsNullOrWhiteSpace(task.DueState)));
    }

    [Fact]
    public async Task AuthenticatedDryRunActionPreservesContractWithoutExecuting()
    {
        using var baseFactory = new WebApplicationFactory<Program>();
        using var factory = baseFactory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<ILocalSessionService>();
                services.AddSingleton<ILocalSessionService, TestAdministratorSession>();
            }));
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add(
            "X-RoamSentinel-CSRF",
            "test-csrf");

        var response = await client.PostAsJsonAsync(
            "/api/actions/kill-process",
            new KillProcessRequest(Environment.ProcessId));
        var result = await response.Content.ReadFromJsonAsync<ActionResultDto>();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(result);
        Assert.True(result.Ok);
        Assert.Contains("Dry run", result.Output);
    }

    [Fact]
    public async Task AuthenticatedCodeGateScanReturnsBlockVerdict()
    {
        using var baseFactory = new WebApplicationFactory<Program>();
        using var factory = baseFactory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<ILocalSessionService>();
                services.AddSingleton<ILocalSessionService, TestAdministratorSession>();
            }));
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add(
            "X-RoamSentinel-CSRF",
            "test-csrf");

        var response = await client.PostAsJsonAsync(
            "/api/modules/codegate/scan",
            new CodeGateScanRequest(
                "const password = \"12345678901234567890\";",
                "contract",
                "sample.js"));
        var result = await response.Content
            .ReadFromJsonAsync<CodeGateScanResult>();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(result);
        Assert.Equal("block", result.Verdict);
        Assert.True(result.RiskScore >= 80);
    }

    [Fact]
    public async Task AuthenticatedMcpToolCallEvaluatesAndReturnsBlock()
    {
        using var baseFactory = new WebApplicationFactory<Program>();
        using var factory = baseFactory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<ILocalSessionService>();
                services.AddSingleton<ILocalSessionService, TestAdministratorSession>();
            }));
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add(
            "X-RoamSentinel-CSRF",
            "test-csrf");

        var response = await client.PostAsJsonAsync(
            "/api/v1/agents/mcp-events",
            new McpToolCallRequest(
                "claude-code",
                "terminal",
                "execute_command",
                """{"command":"rm -rf /var/data"}"""));
        var result = await response.Content
            .ReadFromJsonAsync<McpToolCallEventDto>();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(result);
        Assert.Equal("Block", result.Verdict);
        Assert.Equal(90, result.RiskScore);
        Assert.Equal("claude-code", result.AgentKey);
    }

    [Fact]
    public async Task PersonalProtectionProfileDescribesMinimalLocalControls()
    {
        using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var profile = await client.GetFromJsonAsync<PersonalProtectionProfileDto>(
            "/api/v1/device-shield/personal-protection");

        Assert.NotNull(profile);
        Assert.Equal("PersonalProtectionMinimal", profile.Mode);
        Assert.Contains(
            profile.Controls,
            control => control.Id == "pp-codegate-staging" &&
                control.Status == "available");
        Assert.Contains(
            profile.Controls,
            control => control.Id == "pp-autonomous-remediation" &&
                control.Status == "not-enabled");
    }

    [Fact]
    public async Task ModuleExperienceManifestDefinesIsolatedWorkspaces()
    {
        using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var manifest = await client
            .GetFromJsonAsync<ModuleExperienceManifestDto>(
                "/api/v1/module-experiences");

        Assert.NotNull(manifest);
        Assert.Equal("1.0", manifest.SchemaVersion);
        Assert.Contains(
            manifest.Workspaces,
            workspace => workspace.Id == "protect" &&
                workspace.Views.Contains("overview"));
        Assert.Contains(
            manifest.Workspaces,
            workspace => workspace.Id == "govern" &&
                workspace.DefaultView == "agents");
        Assert.Contains(
            manifest.Workspaces,
            workspace => workspace.Id == "devops" &&
                workspace.DefaultView == "devopsSummary");
        Assert.Contains(
            manifest.Modules,
            module => module.ModuleId == "rs-codegate" &&
                module.Workspace == "codegate" &&
                module.WriteEndpoints.Contains("/api/v1/codegate/scan-path"));
        Assert.All(manifest.Modules, module =>
            Assert.Equal(
                "single-runtime-isolated-contract",
                module.IsolationStatus));
    }

    [Fact]
    public async Task CodeGateCsvReportsRequireAnalystAndReturnCsv()
    {
        using var unauthenticatedFactory = new WebApplicationFactory<Program>();
        using var unauthenticatedClient = unauthenticatedFactory.CreateClient();

        var denied = await unauthenticatedClient.GetAsync(
            "/api/v1/codegate/reports/submissions.csv");

        using var baseFactory = new WebApplicationFactory<Program>();
        using var factory = baseFactory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<ILocalSessionService>();
                services.AddSingleton<ILocalSessionService, TestAdministratorSession>();
            }));
        using var client = factory.CreateClient();

        var submissions = await client.GetAsync(
            "/api/v1/codegate/reports/submissions.csv?verdict=block");
        var gitPushes = await client.GetAsync(
            "/api/v1/codegate/reports/git-pushes.csv?repository=test&actor=admin");
        var bundles = await client.GetAsync(
            "/api/v1/codegate/reports/offline-bundles.csv?bundleType=rules");

        Assert.Contains(
            denied.StatusCode,
            new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden });
        Assert.Equal(HttpStatusCode.OK, submissions.StatusCode);
        Assert.Equal(HttpStatusCode.OK, gitPushes.StatusCode);
        Assert.Equal(HttpStatusCode.OK, bundles.StatusCode);
        Assert.StartsWith(
            "text/csv",
            submissions.Content.Headers.ContentType?.MediaType);
        Assert.Contains(
            "submission_id,evaluated_at,actor,source",
            await submissions.Content.ReadAsStringAsync());
        Assert.Contains(
            "audit_id,observed_at,actor,repository_name",
            await gitPushes.Content.ReadAsStringAsync());
        Assert.Contains(
            "bundle_id,imported_at,component,bundle_type",
            await bundles.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task CodeGateDetailEndpointsReturnPersistedEvidence()
    {
        var scanRoot = Path.Combine(_root, "codegate-detail");
        Directory.CreateDirectory(scanRoot);
        await File.WriteAllTextAsync(
            Path.Combine(scanRoot, "deploy.ps1"),
            "powershell -EncodedCommand SQBFAFgA");

        using var baseFactory = new WebApplicationFactory<Program>();
        using var factory = baseFactory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<ILocalSessionService>();
                services.AddSingleton<ILocalSessionService, TestAdministratorSession>();
            }));
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add(
            "X-RoamSentinel-CSRF",
            "test-csrf");

        var submissionResponse = await client.PostAsJsonAsync(
            "/api/v1/codegate/scan-path",
            new CodeGatePathScanRequest(
                scanRoot,
                "detail-test",
                "rev-1"));
        var submission = await submissionResponse.Content
            .ReadFromJsonAsync<CodeGateSubmissionDto>();
        var auditResponse = await client.PostAsJsonAsync(
            "/api/v1/codegate/git-push",
            new CodeGateGitPushRequest(
                scanRoot,
                "research-app",
                "refs/heads/main",
                "",
                "old",
                "new",
                scanRoot,
                ["deploy.ps1"]));
        var audit = await auditResponse.Content
            .ReadFromJsonAsync<CodeGateGitPushAuditDto>();

        var submissionDetail = await client.GetFromJsonAsync<CodeGateSubmissionDto>(
            $"/api/v1/codegate/submissions/{submission!.SubmissionId}");
        var gitPushDetail = await client.GetFromJsonAsync<CodeGateGitPushAuditDto>(
            $"/api/v1/codegate/git-pushes/{audit!.AuditId}");
        var invalid = await client.GetAsync(
            "/api/v1/codegate/submissions/bad%24id");

        Assert.Equal(HttpStatusCode.OK, submissionResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, auditResponse.StatusCode);
        Assert.NotNull(submissionDetail);
        Assert.NotNull(gitPushDetail);
        Assert.Equal(submission.SubmissionId, submissionDetail.SubmissionId);
        Assert.NotEmpty(submissionDetail.Findings);
        Assert.Equal(audit.AuditId, gitPushDetail.AuditId);
        Assert.Contains("deploy.ps1", gitPushDetail.ChangedFiles);
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
    }

    [Fact]
    public async Task MobileBridgePairingRequiresAdministratorAndEnrollsDevice()
    {
        using var unauthenticatedFactory = new WebApplicationFactory<Program>();
        using var unauthenticatedClient = unauthenticatedFactory.CreateClient();

        var denied = await unauthenticatedClient.PostAsJsonAsync(
            "/api/mobile-bridge/pairing-sessions",
            new { });

        using var baseFactory = new WebApplicationFactory<Program>();
        using var factory = baseFactory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<ILocalSessionService>();
                services.AddSingleton<ILocalSessionService, TestAdministratorSession>();
            }));
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add(
            "X-RoamSentinel-CSRF",
            "test-csrf");

        var pairingResponse = await client.PostAsJsonAsync(
            "/api/mobile-bridge/pairing-sessions",
            new { });
        var pairing = await pairingResponse.Content
            .ReadFromJsonAsync<MobilePairingSessionDto>();
        var enrollmentResponse = await client.PostAsJsonAsync(
            "/api/mobile-bridge/enroll",
            new MobileEnrollmentRequest(
                pairing!.PairingCode,
                "android-contract-1",
                "Android Contract Device",
                "Android",
                "Google",
                "Pixel",
                "15",
                "0.1.0"));
        var enrollment = await enrollmentResponse.Content
            .ReadFromJsonAsync<MobileEnrollmentResultDto>();
        var heartbeatResponse = await client.PostAsJsonAsync(
            "/api/mobile-bridge/heartbeat",
            new MobileHeartbeatRequest(
                enrollment!.DeviceToken,
                enrollment.DeviceId,
                74,
                true,
                32000,
                true,
                false,
                false,
                false,
                false,
                DateTimeOffset.UtcNow));
        var heartbeat = await heartbeatResponse.Content
            .ReadFromJsonAsync<MobileDeviceDto>();

        Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
        Assert.Equal(HttpStatusCode.OK, pairingResponse.StatusCode);
        Assert.NotNull(pairing);
        Assert.Matches("^\\d{6}$", pairing.PairingCode);
        Assert.StartsWith("rs://pair?c=", pairing.PairingPayload);
        Assert.Contains("&b=", pairing.PairingPayload);
        Assert.Equal("rs://pair", pairing.PairingScheme);
        Assert.Equal(HttpStatusCode.OK, enrollmentResponse.StatusCode);
        Assert.NotNull(enrollment);
        Assert.True(enrollment.Ok);
        Assert.False(string.IsNullOrWhiteSpace(enrollment.DeviceToken));
        Assert.Equal(HttpStatusCode.OK, heartbeatResponse.StatusCode);
        Assert.NotNull(heartbeat);
        Assert.Equal(enrollment.DeviceId, heartbeat.DeviceId);
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable(
            RuntimePathService.ProgramDataOverride,
            _previousProgramData);
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(_root))
        {
            try
            {
                Directory.Delete(_root, recursive: true);
            }
            catch (IOException)
            {
                // Test-host shutdown can release SQLite asynchronously.
            }
        }
    }

    private sealed class TestAdministratorSession : ILocalSessionService
    {
        private static readonly LocalSession Session = new(
            "test-session",
            "Administrator",
            "test-csrf",
            DateTimeOffset.UtcNow.AddHours(1));

        public SessionDto Login(
            string token,
            IPAddress? remoteAddress,
            HttpResponse response) =>
            GetSession(new DefaultHttpContext().Request);

        public SessionDto GetSession(HttpRequest request) =>
            new(true, "Administrator", "test-csrf", Session.ExpiresAt);

        public LocalSession? Resolve(HttpRequest request) => Session;
        public void Logout(HttpRequest request, HttpResponse response) { }
        public bool HasRole(LocalSession? session, string requiredRole) => true;
        public bool ValidateCsrf(LocalSession? session, string? token) =>
            token == "test-csrf";
    }
}

[CollectionDefinition("Endpoint contracts", DisableParallelization = true)]
public sealed class EndpointContractCollection;
