using System.IO.Compression;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using RoamSentinel.Config;
using RoamSentinel.Core;
using RoamSentinel.Database;
using RoamSentinel.Database.Migrations;
using RoamSentinel.Logs;

namespace RoamSentinel.Tests;

public sealed class DatabaseMigrationTests : IDisposable
{
    private readonly string _testRoot = Path.Combine(
        Path.GetTempPath(),
        "RoamSentinel.Tests",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public void Migrate_CreatesRequiredSchemaAndIsIdempotent()
    {
        var factory = CreateFactory();
        var runner = new DatabaseMigrationRunner(
            factory,
            [
                new InitialSchemaMigration(),
                new NormalizedTelemetryMigration(),
                new UnifiedDetectionMigration(),
                new LegacyDetectionMappingCleanupMigration(),
                new MitreCoverageMigration(),
                new ThreatIntelligenceMigration(),
                new ResponseControlMigration(),
                new AgentGovernanceMigration(),
                new AgentCatalogSafetyMigration(),
                new DeviceIntegrityMigration(),
                new MobileBridgeMigration(),
                new AppActivityMalwareGuardMigration(),
                new ProtectionFindingsCodeGateMigration(),
                new CodeGateGitTraceabilityMigration(),
                new CodeGateOfflineBundleMigration(),
                new ProtectionSchedulerMigration(),
                new AgentGovernanceExpansionMigration(),
                new McpGovernanceMigration()
            ]);

        runner.Migrate();
        runner.Migrate();

        var status = new DatabaseStatusRepository(factory).GetStatus();
        Assert.Equal("SQLite", status.Provider);
        Assert.Equal(2026092702, status.LatestMigration);
        Assert.Equal(18, status.AppliedMigrationCount);
        Assert.Equal(44, status.TableRowCounts.Count);
        Assert.Contains("security_events", status.TableRowCounts.Keys);
        Assert.Contains("audit_log", status.TableRowCounts.Keys);
        Assert.Contains("system_settings", status.TableRowCounts.Keys);
        Assert.Contains("protection_scheduler_tasks", status.TableRowCounts.Keys);
        Assert.Contains("agent_egress_rules", status.TableRowCounts.Keys);
        Assert.Contains("codegate_active_rules", status.TableRowCounts.Keys);
        Assert.Contains("mcp_tool_events", status.TableRowCounts.Keys);
        Assert.Equal(15, status.TableRowCounts["agent_catalog"]);
    }

    [Fact]
    public void AgentEgressRule_UpsertAndRemove_ProducesAuditLogEntry()
    {
        var factory = CreateMigratedFactory();
        var repository = new AgentEgressRuleRepository(factory);
        var audit = new AuditRepository(factory);

        var rule = new AgentEgressRuleDto(
            "rule-1",
            "claude-code",
            @"C:\npm\claude.cmd",
            "RS Agent Block claude",
            "Outbound",
            "Block",
            DateTimeOffset.UtcNow,
            "Administrator");

        repository.Upsert(rule);

        var stored = repository.FindByPath(@"C:\npm\claude.cmd");
        Assert.NotNull(stored);
        Assert.Equal("claude-code", stored.AgentKey);
        Assert.Equal("Block", stored.Action);
        Assert.Contains(
            audit.GetRecent(10),
            entry => entry.Action == "agent_egress.rule_upserted" &&
                     entry.EntityId == @"C:\npm\claude.cmd");

        var removed = repository.Remove(@"C:\npm\claude.cmd");
        Assert.True(removed);
        Assert.Null(repository.FindByPath(@"C:\npm\claude.cmd"));
        Assert.Contains(
            audit.GetRecent(10),
            entry => entry.Action == "agent_egress.rule_removed" &&
                     entry.EntityId == @"C:\npm\claude.cmd");
    }

    [Fact]
    public void McpTelemetryRepository_RecordAndSummary_CalculatesAndAudits()
    {
        var factory = CreateMigratedFactory();
        var repository = new McpTelemetryRepository(factory);
        var audit = new AuditRepository(factory);

        var toolCall = new McpToolCallEventDto(
            "mcp-event-1",
            DateTimeOffset.UtcNow,
            "claude-code",
            "filesystem",
            "read_file",
            """{"path":"C:\\dev\\src\\index.ts"}""",
            "File read ok",
            10,
            "Info",
            "Allow",
            "Within policy",
            1234,
            "127.0.0.1");

        repository.RecordEvent(toolCall);

        var recent = repository.GetRecentEvents(10);
        var stored = Assert.Single(recent);
        Assert.Equal("mcp-event-1", stored.EventId);
        Assert.Equal("claude-code", stored.AgentKey);
        Assert.Equal("filesystem", stored.ServerName);
        Assert.Equal("read_file", stored.ToolName);

        var summary = repository.GetSummary(10);
        Assert.Equal(1, summary.TotalCount);
        Assert.Equal(0, summary.BlockedCount);
        Assert.Equal(0, summary.WarnedCount);
        Assert.Contains("filesystem", summary.DistinctServers);
        Assert.Contains("read_file", summary.DistinctTools);

        Assert.Contains(
            audit.GetRecent(10),
            entry => entry.Action == "agent_mcp.tool_called" &&
                     entry.EntityId == "mcp-event-1");
    }

    [Fact]
    public void McpGovernanceService_AssessAndRecord_EnforcesPolicyAndEmitsAlerts()
    {
        var factory = CreateMigratedFactory();
        var telemetry = new McpTelemetryRepository(factory);
        var events = new EventRepository(factory);
        var service = new RoamSentinel.AgentGovernance.McpGovernanceService(telemetry, events);

        // 1. Destructive command => Block
        var blocked = service.AssessAndRecord(
            new McpToolCallRequest(
                "antigravity",
                "terminal",
                "execute_command",
                """{"command":"rm -rf /"}"""),
            "analyst");

        Assert.Equal("Block", blocked.Verdict);
        Assert.Equal(90, blocked.RiskScore);
        Assert.Equal("High", blocked.Severity);
        Assert.Contains("Destructive shell", blocked.PolicyReason);

        // 2. Sensitive credential access => Warn
        var warned = service.AssessAndRecord(
            new McpToolCallRequest(
                "goose-ai",
                "filesystem",
                "read_file",
                """{"path":"C:\\project\\.env"}"""),
            "analyst");

        Assert.Equal("Warn", warned.Verdict);
        Assert.Equal(80, warned.RiskScore);
        Assert.Contains("Sensitive credential", warned.PolicyReason);

        // 3. Normal file reading => Allow
        var allowed = service.AssessAndRecord(
            new McpToolCallRequest(
                "continue-dev",
                "filesystem",
                "read_file",
                """{"path":"C:\\project\\README.md"}"""),
            "analyst");

        Assert.Equal("Allow", allowed.Verdict);
        Assert.Equal(10, allowed.RiskScore);

        // Check alerts recorded for Block and Warn, but not Allow
        var alertList = events.GetRecent(10);
        Assert.Contains(alertList, alert => alert.Category == "Agent Governance" && alert.Title.Contains("antigravity"));
        Assert.Contains(alertList, alert => alert.Category == "Agent Governance" && alert.Title.Contains("goose-ai"));
        Assert.DoesNotContain(alertList, alert => alert.Title.Contains("continue-dev"));

        // Check summary
        var summary = service.GetSummary(10);
        Assert.Equal(3, summary.TotalCount);
        Assert.Equal(1, summary.BlockedCount);
        Assert.Equal(1, summary.WarnedCount);
    }

    [Fact]
    public void EventWrite_ProducesAuditLogEntry()
    {
        var factory = CreateMigratedFactory();
        var events = new EventRepository(factory);
        var audit = new AuditRepository(factory);

        events.TryAdd(new AlertDto(
            "event-1",
            DateTimeOffset.UtcNow,
            "Test",
            "Low",
            "Test event",
            "Evidence"));

        var auditEntries = audit.GetRecent(10);
        Assert.Contains(
            auditEntries,
            entry =>
                entry.Action == "security_event.created" &&
                entry.EntityId == "event-1");
    }

    [Fact]
    public void AgentPolicyWrite_ProducesAuditAndActivityEntries()
    {
        var factory = CreateMigratedFactory();
        var policies = new AgentPolicyRepository(factory);

        policies.Save(new AgentPolicy(
            [@"C:\Tools\agent.exe"],
            []));

        var status = new DatabaseStatusRepository(factory).GetStatus();
        var audit = new AuditRepository(factory).GetRecent(10);
        Assert.Equal(1, status.TableRowCounts["agent_registry"]);
        Assert.Equal(1, status.TableRowCounts["agent_activity"]);
        Assert.Contains(
            audit,
            entry => entry.Action == "agent_policy.saved");
    }

    [Fact]
    public void AgentRegistry_PreservesFirstSeenAndTracksRiskAndNetwork()
    {
        var factory = CreateMigratedFactory();
        var repository = new AgentRegistryRepository(factory);
        var firstSeen = DateTimeOffset.UtcNow.AddMinutes(-5);
        var lastSeen = DateTimeOffset.UtcNow;
        var initial = new AgentGovernanceDto(
            "cursor",
            "Cursor",
            @"C:\Tools\Cursor.exe",
            "Anysphere",
            "unknown",
            firstSeen,
            firstSeen,
            true,
            100,
            1,
            1,
            firstSeen,
            55,
            "Agent path is not explicitly trusted.",
            false,
            true);
        repository.UpsertObservations([initial], firstSeen);
        repository.UpsertObservations(
            [
                initial with
                {
                    LastSeen = lastSeen,
                    NetworkConnectionCount = 4,
                    DistinctRemoteAddressCount = 3,
                    NetworkLastSeen = lastSeen,
                    RiskScore = 80,
                    RiskReason = "Agent has unusual public network activity."
                }
            ],
            lastSeen);

        var stored = Assert.Single(repository.GetAll());
        Assert.Equal(firstSeen, stored.FirstSeen);
        Assert.Equal(lastSeen, stored.LastSeen);
        Assert.Equal(4, stored.NetworkConnectionCount);
        Assert.Equal(80, stored.RiskScore);
        Assert.Contains(
            repository.GetDefinitions(),
            item => item.Name == "ChatGPT Desktop");
        Assert.Contains(
            repository.GetDefinitions(),
            item => item.Name == "VS Code Copilot");
        Assert.Contains(
            new AuditRepository(factory).GetRecent(10),
            item => item.Action == "agent_governance.observed");
    }

    [Fact]
    public void AgentRegistry_EmptyObservationMarksMissingAgentStopped()
    {
        var factory = CreateMigratedFactory();
        var repository = new AgentRegistryRepository(factory);
        var observedAt = DateTimeOffset.UtcNow.AddMinutes(-1);
        repository.UpsertObservations(
        [
            new AgentGovernanceDto(
                "cursor",
                "Cursor",
                @"C:\Tools\Cursor.exe",
                "Anysphere",
                "unknown",
                observedAt,
                observedAt,
                true,
                100,
                2,
                2,
                observedAt,
                55,
                "Agent path is not explicitly trusted.",
                false,
                true)
        ],
        observedAt);

        repository.UpsertObservations([], observedAt.AddMinutes(1));

        var stored = Assert.Single(repository.GetAll());
        Assert.False(stored.IsRunning);
        Assert.Null(stored.ProcessId);
        Assert.Equal(0, stored.NetworkConnectionCount);
        Assert.Equal(0, stored.DistinctRemoteAddressCount);
        Assert.Equal(observedAt, stored.FirstSeen);
    }

    [Fact]
    public void IpBlockWrite_ProducesAuditLogEntry()
    {
        var factory = CreateMigratedFactory();
        var blocks = new IpBlockRepository(factory);

        blocks.Upsert(new IpBlockDto(
            "203.0.113.7",
            "Test block",
            DateTimeOffset.UtcNow));

        var audit = new AuditRepository(factory).GetRecent(10);
        Assert.Contains(
            audit,
            entry =>
                entry.Action == "ip_block.upserted" &&
                entry.EntityId == "203.0.113.7");
    }

    [Fact]
    public void SystemSettingWrite_IsWhitelistedParameterizedAndAudited()
    {
        var factory = CreateMigratedFactory();
        var settings = new SystemSettingsRepository(
            factory,
            NullStructuredLogService.Instance);

        var updated = settings.Set(
            "dashboard.refresh_interval_ms",
            "5000",
            "Administrator");

        Assert.Equal("5000", updated.Value);
        Assert.Throws<ArgumentException>(() => settings.Set(
            "database.connection_string",
            "unsafe",
            "Administrator"));
        Assert.Contains(
            new AuditRepository(factory).GetRecent(10),
            item =>
                item.Action == "settings.changed" &&
                item.EntityId == "dashboard.refresh_interval_ms");
    }

    [Fact]
    public void ResponseActionWrite_ProducesAuditLogEntry()
    {
        var factory = CreateMigratedFactory();
        var responses = new ResponseActionRepository(
            factory,
            NullStructuredLogService.Instance);

        responses.Record(new ResponseActionRecord(
            "action-1",
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow,
            "block_ip",
            "invalid",
            "Rejected",
            false,
            "",
            "Invalid IP address.",
            "local-user",
            """{"blocked":false}""",
            """{"blocked":false}"""));

        var status = new DatabaseStatusRepository(factory).GetStatus();
        var audit = new AuditRepository(factory).GetRecent(10);
        var recorded = responses.GetRecent(10).Single();
        Assert.Equal(1, status.TableRowCounts["response_actions"]);
        Assert.Equal("""{"blocked":false}""", recorded.BeforeJson);
        Assert.Equal("""{"blocked":false}""", recorded.AfterJson);
        Assert.Contains(
            audit,
            entry =>
                entry.Action == "response.block_ip" &&
                !entry.Success);
    }

    [Fact]
    public void ResponseActionLog_ReturnsNewestFirstWithOutcomeEvidence()
    {
        var factory = CreateMigratedFactory();
        var responses = new ResponseActionRepository(
            factory,
            NullStructuredLogService.Instance);
        var now = DateTimeOffset.UtcNow;
        responses.Record(new ResponseActionRecord(
            "action-old",
            now.AddMinutes(-1),
            now.AddMinutes(-1),
            "kill_process",
            "42",
            "Completed",
            true,
            "Process stopped.",
            "",
            "Administrator",
            """{"running":true}""",
            """{"running":false}"""));
        responses.Record(new ResponseActionRecord(
            "action-new",
            now,
            now,
            "block_ip",
            "203.0.113.8",
            "Failed",
            false,
            "",
            "Firewall command failed.",
            "Administrator",
            """{"blocked":false}""",
            """{"blocked":false}"""));

        var recorded = responses.GetRecent(10);

        Assert.Equal(
            ["action-new", "action-old"],
            recorded.Select(item => item.ActionId));
        Assert.Equal(
            "Firewall command failed.",
            recorded[0].Error);
        Assert.Equal("""{"running":true}""", recorded[1].BeforeJson);
        Assert.Equal("""{"running":false}""", recorded[1].AfterJson);
    }

    [Fact]
    public void AlertDisposition_PersistsReviewStateAndAudit()
    {
        var factory = CreateMigratedFactory();
        var events = new EventRepository(factory);
        events.TryAdd(new AlertDto(
            "event-review",
            DateTimeOffset.UtcNow,
            "Execution",
            "High",
            "Review me",
            "Evidence"));

        var updated = events.SetDisposition(
            "event-review",
            "false_positive",
            "Known administrative tool",
            "authorized-local-operator");

        Assert.NotNull(updated);
        Assert.Equal("false_positive", updated.Status);
        Assert.Equal("Known administrative tool", updated.ResolutionNote);
        Assert.NotNull(updated.ResolvedAt);
        Assert.Contains(
            new AuditRepository(factory).GetRecent(10),
            entry =>
                entry.Action == "security_event.disposition_changed" &&
                entry.EntityId == "event-review");
    }

    [Fact]
    public void TelemetrySnapshot_PersistsEveryNormalizedDomainAndAudit()
    {
        var factory = CreateMigratedFactory();
        var observedAt = DateTimeOffset.UtcNow;
        var repository = new TelemetryRepository(
            factory,
            new DatabaseOptions
            {
                FilePath = "test.db",
                ImportLegacyJson = false,
                PersistTelemetrySnapshots = true,
                TelemetryPersistenceIntervalSeconds = 1
            });
        var snapshot = new TelemetrySnapshot(
            observedAt,
            [new ConnectionTelemetry(
                "TCP", "127.0.0.1", 5000, "127.0.0.1", 5117,
                "Established", 10, "test", @"C:\test.exe")],
            [new ProcessTelemetry(
                10, "test", @"C:\test.exe", 10, 8, 1, 5, 2, 1,
                observedAt, 4, "parent", "test.exe --run")],
            [new StartupTelemetry("startup", @"C:\test.exe", "HKCU")],
            [new ScheduledTaskTelemetry(
                "task", "\\", "Ready", true, "user", "test.exe", "", "Logon")],
            [new ServiceTelemetry(
                "service", "Service", "Running", "Auto",
                @"C:\service.exe", 20, "LocalSystem")],
            new DefenderStatusDto(
                true, true, true, true, 1, 2, observedAt, "1.0", ""),
            new FirewallStatusDto(
                true,
                true,
                [new FirewallProfileTelemetry(
                    "Domain", true, "Block", "Allow", false)],
                ""),
            [new AgentInstallationTelemetry(
                "Codex", @"C:\codex.exe", "1", "OpenAI",
                "Running process", true, 30)],
            [new SuspiciousPathTelemetry(
                @"C:\Users\User\AppData\Roaming\run.exe",
                "Process",
                "run",
                "User-writable path")]);

        Assert.True(repository.PersistSnapshot(snapshot));

        var status = new DatabaseStatusRepository(factory).GetStatus();
        foreach (var table in new[]
        {
            "telemetry_processes",
            "telemetry_network",
            "telemetry_startup",
            "telemetry_scheduled_tasks",
            "telemetry_services",
            "telemetry_defender",
            "telemetry_firewall",
            "telemetry_ai_agents",
            "telemetry_suspicious_paths"
        })
        {
            Assert.Equal(1, status.TableRowCounts[table]);
        }

        Assert.Contains(
            new AuditRepository(factory).GetRecent(10),
            entry => entry.Action == "telemetry.snapshot.persisted");
    }

    [Fact]
    public void DetectionRuleStateChange_IsPersistedAndAudited()
    {
        var factory = CreateMigratedFactory();
        var rules = new DetectionRuleRepository(factory);

        var updated = rules.SetEnabled("RS-EXEC-001", false);

        Assert.NotNull(updated);
        Assert.False(updated.Enabled);
        Assert.Equal("Execution", updated.Category);
        Assert.Contains(
            updated.MitreMappings,
            mapping => mapping.TechniqueId == "T1059.001");
        Assert.Contains(
            new AuditRepository(factory).GetRecent(10),
            entry =>
                entry.Action == "detection_rule.enabled_changed" &&
                entry.EntityId == "RS-EXEC-001");
    }

    [Fact]
    public void SeededDetectionRules_HaveValidRiskAndMitreMappings()
    {
        var factory = CreateMigratedFactory();
        var rules = new DetectionRuleRepository(factory).GetAll();
        var validSeverities = new HashSet<string>(
            ["Info", "Low", "Medium", "High", "Critical"],
            StringComparer.OrdinalIgnoreCase);

        Assert.NotEmpty(rules);
        Assert.All(
            rules,
            rule =>
            {
                Assert.Contains(rule.Severity, validSeverities);
                Assert.InRange(rule.RiskWeight, 0, 100);
                Assert.InRange(rule.Confidence, 0, 100);
                if (rule.Enabled)
                {
                    Assert.NotEmpty(rule.MitreMappings);
                }
                Assert.All(
                    rule.MitreMappings,
                    mapping => Assert.Matches(
                        @"^T\d{4}(?:\.\d{3})?$",
                        mapping.TechniqueId));
            });
    }

    [Fact]
    public void DatabaseLayer_EnforcesMitreMappingForeignKey()
    {
        var factory = CreateMigratedFactory();
        using var connection = factory.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO mitre_mappings (
                rule_id, tactic, technique_id, technique_name
            ) VALUES (
                'missing-rule', 'Execution', 'T1059', 'Command Interpreter'
            );
            """;

        Assert.Throws<SqliteException>(() => command.ExecuteNonQuery());
    }

    [Fact]
    public void BackupExport_CreatesRestorableArchiveAndAuditEntry()
    {
        var factory = CreateMigratedFactory();
        var audit = new AuditRepository(factory);
        var service = new BackupExportService(
            factory,
            new DatabaseStatusRepository(factory),
            audit,
            NullStructuredLogService.Instance);

        var export = service.Create("Administrator");

        Assert.EndsWith(".zip", export.FileName);
        Assert.Equal("application/zip", export.ContentType);
        using var stream = new MemoryStream(export.Content);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read);
        Assert.NotNull(archive.GetEntry("roamsentinel.db"));
        Assert.NotNull(archive.GetEntry("RESTORE.txt"));
        var manifestEntry = Assert.IsType<ZipArchiveEntry>(
            archive.GetEntry("manifest.json"));
        using var manifestStream = manifestEntry.Open();
        using var manifest = JsonDocument.Parse(manifestStream);
        Assert.Equal(
            ProductInfo.Name,
            manifest.RootElement.GetProperty("product").GetString());
        Assert.False(
            manifest.RootElement.GetProperty("containsSecrets").GetBoolean());
        var databaseEntry = Assert.IsType<ZipArchiveEntry>(
            archive.GetEntry("roamsentinel.db"));
        var restoredPath = Path.Combine(_testRoot, "restored.db");
        using (var restoredFile = File.Create(restoredPath))
        using (var databaseStream = databaseEntry.Open())
        {
            databaseStream.CopyTo(restoredFile);
        }
        using var restored = new SqliteConnection(
            $"Data Source={restoredPath};Mode=ReadOnly");
        restored.Open();
        using var migrationCommand = restored.CreateCommand();
        migrationCommand.CommandText =
            "SELECT COUNT(*) FROM schema_migrations;";
        Assert.Equal(18L, (long)Assert.IsType<long>(
            migrationCommand.ExecuteScalar()));

        Assert.Contains(
            audit.GetRecent(10),
            entry =>
                entry.Action == "backup.exported" &&
                entry.Success);
    }

    [Fact]
    public void DeviceIntegrityRepository_BaselinesThenEmitsExplainableChanges()
    {
        var factory = CreateMigratedFactory();
        var repository = new DeviceIntegrityRepository(factory);
        var first = CreateIntegritySnapshot(
            [new("driver-a", "Driver A", "Running", "Auto", "a.sys", "Kernel")]);
        var second = CreateIntegritySnapshot(
            [new("driver-b", "Driver B", "Running", "Auto", "b.sys", "Kernel")]);

        Assert.Empty(repository.RecordSnapshot(first));
        var changes = repository.RecordSnapshot(second);

        Assert.Equal(2, changes.Count);
        Assert.Contains(changes, item =>
            item.EntityKey == "driver-a" && item.ChangeType == "removed");
        Assert.Contains(changes, item =>
            item.EntityKey == "driver-b" && item.ChangeType == "added");
        Assert.All(changes, item => Assert.NotEmpty(item.Explanation));
        Assert.Equal(2, repository.GetRecentEvents(10).Count);
    }

    [Fact]
    public void DeviceIntegrityFindings_ProjectChangesAndPersistStatus()
    {
        var factory = CreateMigratedFactory();
        var repository = new DeviceIntegrityRepository(factory);
        var findings = new DeviceIntegrityFindingRepository(factory);
        var first = CreateIntegritySnapshot(
            [new("driver-a", "Driver A", "Running", "Auto", "a.sys", "Kernel")]);
        var second = CreateIntegritySnapshot(
            [new("driver-b", "Driver B", "Running", "Auto", "b.sys", "Kernel")]);

        Assert.Empty(repository.RecordSnapshot(first));
        var changes = repository.RecordSnapshot(second);
        var projected = findings.RecordFromChanges(changes);
        var updated = findings.SetStatus(
            projected[0].FindingId,
            "expected",
            "Approved maintenance",
            "Analyst");

        Assert.Equal(2, projected.Count);
        Assert.NotNull(updated);
        Assert.Equal("expected", updated.Status);
        Assert.Contains(
            new AuditRepository(factory).GetRecent(10),
            entry => entry.Action == "device_integrity.finding_status_changed");
    }

    [Fact]
    public void CodeGatePathScan_RecordsSubmissionAndRedactsSecretEvidence()
    {
        var factory = CreateMigratedFactory();
        var repository = new CodeGateRepository(factory);
        var service = new RoamSentinel.CodeGate.CodeGateService(repository);
        var scanRoot = Path.Combine(_testRoot, "scan");
        Directory.CreateDirectory(scanRoot);
        File.WriteAllText(
            Path.Combine(scanRoot, "config.env"),
            "API_KEY=\"12345678901234567890\"");

        var result = service.ScanPath(
            new CodeGatePathScanRequest(scanRoot, "git-push", "abc123"),
            "tester");
        var stored = Assert.Single(repository.GetRecentSubmissions(10));

        Assert.Equal("block", result.Verdict);
        Assert.Equal(result.SubmissionId, stored.SubmissionId);
        Assert.Equal(
            result.SubmissionId,
            repository.GetSubmission(result.SubmissionId)?.SubmissionId);
        Assert.Contains(stored.Findings, finding =>
            finding.RuleId == "CG-SECRET-002" &&
            finding.Evidence.Contains("[REDACTED]") &&
            !finding.Evidence.Contains("12345678901234567890"));
        Assert.Contains(
            new AuditRepository(factory).GetRecent(10),
            entry => entry.Action == "codegate.submission_recorded");
    }

    [Fact]
    public void CodeGateGitPushAudit_RecordsRepositoryBranchAndFiles()
    {
        var factory = CreateMigratedFactory();
        var submissions = new CodeGateRepository(factory);
        var gitAudits = new CodeGateGitAuditRepository(factory);
        var service = new RoamSentinel.CodeGate.CodeGateService(
            submissions,
            gitAudits);
        var scanRoot = Path.Combine(_testRoot, "git-scan");
        Directory.CreateDirectory(scanRoot);
        File.WriteAllText(
            Path.Combine(scanRoot, "deploy-notes.txt"),
            "powershell -EncodedCommand SQBFAFgA");

        var audit = service.RecordGitPush(
            new CodeGateGitPushRequest(
                scanRoot,
                "research-app",
                "refs/heads/main",
                "",
                "old",
                "new",
                scanRoot,
                ["deploy-notes.txt"]),
            "alice");
        var stored = Assert.Single(gitAudits.GetRecent(10));
        var detail = gitAudits.Get(audit.AuditId);

        Assert.Equal(audit.AuditId, stored.AuditId);
        Assert.NotNull(detail);
        Assert.Equal(audit.AuditId, detail.AuditId);
        Assert.Equal(audit.SubmissionId, detail.SubmissionId);
        Assert.Equal("research-app", stored.RepositoryName);
        Assert.Equal("main", stored.Branch);
        Assert.Equal("alice", stored.Actor);
        Assert.Contains("deploy-notes.txt", stored.ChangedFiles);
        Assert.Equal("warn", stored.Verdict);
        Assert.Contains(
            new AuditRepository(factory).GetRecent(10),
            entry => entry.Action == "codegate.git_push_recorded");
    }

    [Fact]
    public void CodeGateOfflineBundleImport_ValidatesHashAndRecordsFreshness()
    {
        var factory = CreateMigratedFactory();
        var repository = new CodeGateBundleRepository(factory);
        var service = new RoamSentinel.CodeGate.CodeGateBundleService(repository);
        var bundlePath = Path.Combine(_testRoot, "codegate-rules.json");
        File.WriteAllText(
            bundlePath,
            """
            {
              "component": "RS CodeGate",
              "bundleType": "codegate-rules",
              "name": "University VM baseline rules",
              "version": "2026.07.20",
              "schemaVersion": "1.0",
              "generatedAt": "2026-07-20T00:00:00Z",
              "source": "offline-admin",
              "signature": "unsigned-test"
            }
            """);

        var imported = service.ImportBundle(
            new CodeGateBundleImportRequest(bundlePath, ""),
            "Administrator");
        var stored = Assert.Single(repository.GetRecent(10));

        Assert.True(imported.Verified);
        Assert.Equal(imported.Sha256, stored.Sha256);
        Assert.Equal("codegate-rules", stored.BundleType);
        Assert.Contains(
            new AuditRepository(factory).GetRecent(10),
            entry => entry.Action == "codegate.offline_bundle_imported");
        Assert.Throws<InvalidDataException>(() => service.ImportBundle(
            new CodeGateBundleImportRequest(bundlePath, "bad-sha"),
            "Administrator"));
    }

    [Fact]
    public void CodeGateActiveRule_SaveAndGetAndAudit_WorksCorrectly()
    {
        var factory = CreateMigratedFactory();
        var repository = new CodeGateActiveRuleRepository(factory);
        var audit = new AuditRepository(factory);

        var rule = new CodeGateActiveRuleDto(
            "CG-CUSTOM-001",
            "bundle-test-1",
            "Block Internal Token",
            "High",
            80,
            @"internal_token_[0-9a-f]{16}",
            "Forbidden internal token detected.",
            true);

        repository.SaveRules("bundle-test-1", [rule]);

        var active = repository.GetActiveRules();
        var retrieved = Assert.Single(active);
        Assert.Equal("CG-CUSTOM-001", retrieved.RuleId);
        Assert.Equal("bundle-test-1", retrieved.BundleId);
        Assert.Equal(80, retrieved.RiskScore);
        Assert.Contains(
            audit.GetRecent(10),
            entry => entry.Action == "codegate.active_rules_saved" &&
                     entry.EntityId == "bundle-test-1");

        repository.DeleteRulesByBundle("bundle-test-1");
        Assert.Empty(repository.GetActiveRules());
        Assert.Contains(
            audit.GetRecent(10),
            entry => entry.Action == "codegate.active_rules_deleted" &&
                     entry.EntityId == "bundle-test-1");
    }

    [Fact]
    public void CodeGateOfflineBundleImport_WithRulesActivatesAndExecutesInScan()
    {
        var factory = CreateMigratedFactory();
        var bundleRepo = new CodeGateBundleRepository(factory);
        var activeRulesRepo = new CodeGateActiveRuleRepository(factory);
        var bundleService = new RoamSentinel.CodeGate.CodeGateBundleService(bundleRepo, activeRulesRepo);
        var codeGateService = new RoamSentinel.CodeGate.CodeGateService(
            new CodeGateRepository(factory),
            new CodeGateGitAuditRepository(factory),
            activeRulesRepo);

        var bundlePath = Path.Combine(_testRoot, "active-rules-bundle.json");
        File.WriteAllText(
            bundlePath,
            """
            {
              "component": "RS CodeGate",
              "bundleType": "codegate-rules",
              "name": "Custom Organization Security Rules",
              "version": "2026.09.27",
              "schemaVersion": "1.0",
              "generatedAt": "2026-09-27T00:00:00Z",
              "source": "offline-admin",
              "signature": "unsigned-test",
              "rules": [
                {
                  "ruleId": "CG-ORG-SECRET-001",
                  "name": "Org Proprietary Key",
                  "severity": "High",
                  "riskScore": 85,
                  "pattern": "ORG_KEY_[A-Z0-9]{12}",
                  "explanation": "Proprietary organization key pattern detected."
                }
              ]
            }
            """);

        var imported = bundleService.ImportBundle(
            new CodeGateBundleImportRequest(bundlePath, ""),
            "Administrator");

        Assert.Equal("active", imported.Status);
        Assert.Contains("1 rules activated", imported.Message);

        var activeRules = codeGateService.GetActiveRules();
        var activeRule = Assert.Single(activeRules);
        Assert.Equal("CG-ORG-SECRET-001", activeRule.RuleId);

        // Test evaluating text with this pattern
        var scanResult = codeGateService.Evaluate(new CodeGateScanRequest(
            "const secret = \"ORG_KEY_ABC123XYZ890\";",
            "inline",
            "config.ts"));

        Assert.Equal("block", scanResult.Verdict);
        Assert.True(scanResult.RiskScore >= 80);
        Assert.Contains(
            scanResult.Findings,
            finding => finding.Contains("Proprietary organization key pattern detected."));
    }

    [Fact]
    public void CodeGateOfflineBundleImport_RejectsInvalidRegexPattern()
    {
        var factory = CreateMigratedFactory();
        var bundleRepo = new CodeGateBundleRepository(factory);
        var activeRulesRepo = new CodeGateActiveRuleRepository(factory);
        var bundleService = new RoamSentinel.CodeGate.CodeGateBundleService(bundleRepo, activeRulesRepo);

        var bundlePath = Path.Combine(_testRoot, "bad-regex-bundle.json");
        File.WriteAllText(
            bundlePath,
            """
            {
              "component": "RS CodeGate",
              "bundleType": "codegate-rules",
              "name": "Malformed Regex Rules",
              "version": "2026.09.27",
              "schemaVersion": "1.0",
              "generatedAt": "2026-09-27T00:00:00Z",
              "source": "offline-admin",
              "signature": "unsigned-test",
              "rules": [
                {
                  "ruleId": "CG-BAD-001",
                  "name": "Bad Regex",
                  "severity": "High",
                  "pattern": "[a-z"
                }
              ]
            }
            """);

        var ex = Assert.Throws<InvalidDataException>(() => bundleService.ImportBundle(
            new CodeGateBundleImportRequest(bundlePath, ""),
            "Administrator"));
        Assert.Contains("invalid regex pattern", ex.Message);
    }

    [Fact]
    public void BackupRestore_ValidatesIntegrityAndReplacesDatabase()
    {
        var factory = CreateMigratedFactory();
        var audit = new AuditRepository(factory);
        var service = new BackupExportService(
            factory,
            new DatabaseStatusRepository(factory),
            audit,
            NullStructuredLogService.Instance);
        var export = service.Create("Administrator");
        new SystemSettingsRepository(
            factory,
            NullStructuredLogService.Instance).Set(
                "logs.retention_days",
                "30",
                "Administrator");

        using var stream = new MemoryStream(export.Content);
        var restored = service.Restore(stream, "Administrator");

        Assert.True(restored.Ok);
        Assert.Equal(64, restored.Sha256.Length);
        Assert.NotEmpty(restored.BackupPath);
        Assert.DoesNotContain(
            new SystemSettingsRepository(
                factory,
                NullStructuredLogService.Instance).GetAll(),
            setting => setting.Key == "logs.retention_days");
    }

    [Fact]
    public void BackupRestore_RejectsTamperedDatabase()
    {
        var factory = CreateMigratedFactory();
        var audit = new AuditRepository(factory);
        var service = new BackupExportService(
            factory,
            new DatabaseStatusRepository(factory),
            audit,
            NullStructuredLogService.Instance);
        var export = service.Create("Administrator");
        export.Content[^20] ^= 0xFF;

        using var stream = new MemoryStream(export.Content);

        Assert.ThrowsAny<InvalidDataException>(() =>
            service.Restore(stream, "Administrator"));
    }

    [Fact]
    public void MitreFindings_PersistHostTimeSeverityAndTechnique()
    {
        var factory = CreateMigratedFactory();
        var repository = new MitreRepository(
            factory,
            new DetectionOptions
            {
                FindingPersistenceIntervalSeconds = 1
            });
        var observedAt = DateTimeOffset.UtcNow;
        var finding = new DetectionFindingDto(
            "finding-1",
            observedAt,
            "RS-EXEC-001",
            "PowerShell encoded command",
            "Execution",
            "Critical",
            90,
            "Encoded PowerShell",
            "Description",
            "powershell.exe -enc ...",
            "process",
            "42",
            []);

        Assert.True(repository.PersistFindings(
            new DetectionResultDto(
                observedAt,
                90,
                "Critical",
                [finding]),
            "TEST-HOST"));

        var events = repository.GetEvents(100);
        Assert.Contains(
            events,
            item =>
                item.FindingId == "finding-1" &&
                item.TechniqueId == "T1059" &&
                item.Tactic == "Execution" &&
                item.Severity == "Critical" &&
                item.Host == "TEST-HOST" &&
                item.LastSeenAt == observedAt);
        var techniques = repository.GetTechniques();
        foreach (var techniqueId in new[]
        {
            "T1059", "T1547", "T1053", "T1003",
            "T1021", "T1105", "T1071", "T1562"
        })
        {
            Assert.Contains(
                techniques,
                item => item.TechniqueId == techniqueId);
        }

        Assert.Contains(
            new AuditRepository(factory).GetRecent(10),
            entry => entry.Action == "detection.findings.persisted");
    }

    [Fact]
    public void LocalIocWrite_FeedsDetectionAndIsAudited()
    {
        var factory = CreateMigratedFactory();
        var repository = new ThreatIndicatorRepository(factory);
        var now = DateTimeOffset.UtcNow;
        var indicator = new ThreatIndicatorDto(
            "203.0.113.42",
            "ip",
            "Malicious",
            95,
            "Local",
            now,
            now,
            null,
            "Test IOC",
            ["test"],
            "{}");

        repository.Upsert(indicator, "local-user");

        Assert.Contains(
            "203.0.113.42",
            repository.GetActiveSuspiciousIps(now));
        Assert.NotNull(repository.FindActive(
            "203.0.113.42",
            "ip",
            "Local",
            now));
        Assert.Contains(
            new AuditRepository(factory).GetRecent(10),
            entry => entry.Action == "threat_indicator.upserted");

        Assert.True(repository.RemoveLocal("203.0.113.42", "ip"));
        Assert.DoesNotContain(
            "203.0.113.42",
            repository.GetActiveSuspiciousIps(now));
    }

    [Fact]
    public void ProtectionSchedulerRepository_TracksStatusAndAudit()
    {
        var factory = CreateMigratedFactory();
        var repository = new ProtectionSchedulerRepository(factory);
        var now = DateTimeOffset.UtcNow;

        repository.EnsureTasks(
        [
            new SchedulerTaskStatusDto(
                "telemetry-snapshot",
                "Data egress and process snapshot",
                true,
                300,
                null,
                null,
                now,
                false,
                "pending",
                "",
                0,
                0)
        ]);
        repository.MarkStarted("telemetry-snapshot", now.AddSeconds(1));
        repository.MarkCompleted(
            "telemetry-snapshot",
            now.AddSeconds(2),
            true,
            "ok",
            "Observed 3 outbound flows.",
            now.AddMinutes(5));

        var dashboard = repository.GetDashboard(enabled: true);
        var task = Assert.Single(dashboard.Tasks);
        Assert.True(dashboard.Enabled);
        Assert.Equal("ok", task.LastStatus);
        Assert.Equal(1, task.SuccessCount);
        Assert.Equal(0, task.FailureCount);
        Assert.Equal(
            now.AddMinutes(5).ToUnixTimeSeconds(),
            task.NextRunAt?.ToUnixTimeSeconds());
        Assert.Contains(
            new AuditRepository(factory).GetRecent(10),
            entry => entry.Action == "scheduler.task.completed");
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(_testRoot))
        {
            Directory.Delete(_testRoot, recursive: true);
        }
    }

    private SqliteConnectionFactory CreateFactory() =>
        new(
            _testRoot,
            new DatabaseOptions
            {
                FilePath = "test.db",
                ImportLegacyJson = false,
                PersistTelemetrySnapshots = false
            });

    private SqliteConnectionFactory CreateMigratedFactory()
    {
        var factory = CreateFactory();
        new DatabaseMigrationRunner(
            factory,
            [
                new InitialSchemaMigration(),
                new NormalizedTelemetryMigration(),
                new UnifiedDetectionMigration(),
                new LegacyDetectionMappingCleanupMigration(),
                new MitreCoverageMigration(),
                new ThreatIntelligenceMigration(),
                new ResponseControlMigration(),
                new AgentGovernanceMigration(),
                new AgentCatalogSafetyMigration(),
                new DeviceIntegrityMigration(),
                new MobileBridgeMigration(),
                new AppActivityMalwareGuardMigration(),
                new ProtectionFindingsCodeGateMigration(),
                new CodeGateGitTraceabilityMigration(),
                new CodeGateOfflineBundleMigration(),
                new ProtectionSchedulerMigration(),
                new AgentGovernanceExpansionMigration(),
                new McpGovernanceMigration()
            ]).Migrate();
        return factory;
    }

    private static DeviceIntegritySnapshot CreateIntegritySnapshot(
        IReadOnlyList<DriverInventoryTelemetry> drivers) =>
        new(
            DateTimeOffset.UtcNow,
            drivers,
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            new("RemoteSigned", true, false, false, "5.1"),
            []);
}
