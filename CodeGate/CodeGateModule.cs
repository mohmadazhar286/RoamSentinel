using RoamSentinel.Core;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace RoamSentinel.CodeGate;

public sealed class CodeGateModule : IProductModule
{
    public ModuleRegistration Registration { get; } = new(
        "rs-codegate",
        "CodeGate",
        "RS CodeGate",
        "active",
        [
            "secret-detection",
            "suspicious-script-detection",
            "dependency-vulnerability-analysis",
            "privacy-data-breach-analysis",
            "allow-warn-block-verdict"
        ]);
}

public sealed class CodeGateService(
    ICodeGateRepository? repository = null,
    ICodeGateGitAuditRepository? gitAudit = null,
    ICodeGateActiveRuleRepository? activeRules = null) : ICodeGateService
{
    private const int MaxFiles = 500;
    private const int MaxTextBytesPerFile = 1_000_000;

    private static readonly Regex AssignmentSecret = new(
        @"(?i)(api[_-]?key|access[_-]?token|secret|password|client[_-]?secret)\s*[:=]\s*[""'][^""']{12,}[""']",
        RegexOptions.Compiled);

    private static readonly Regex CloudKey = new(
        @"(?i)(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{35}|gh[pousr]_[0-9A-Za-z_]{30,})",
        RegexOptions.Compiled);

    private static readonly Regex EncodedExecution = new(
        @"(?i)(-encodedcommand|frombase64string|iex\s*\(|invoke-expression|downloadstring|invoke-webrequest|curl\s+https?://)",
        RegexOptions.Compiled);

    private static readonly Regex DestructiveDeploymentCommand = new(
        @"(?i)(rm\s+-rf\s+[/\\]|remove-item\s+.*-recurse\s+.*-force|format-volume|diskpart|bcdedit|takeown\s+/f|icacls\s+.*\s+/grant\s+everyone)",
        RegexOptions.Compiled);

    private static readonly Regex RemoteInstallerPipe = new(
        @"(?i)(curl|wget|invoke-webrequest|iwr)\s+.*https?://.*(\|\s*(sh|bash|powershell|pwsh)|;\s*(sh|bash|powershell|pwsh))",
        RegexOptions.Compiled);

    private static readonly Regex PackageLifecycleScript = new(
        @"(?i)[""'](preinstall|install|postinstall|prepare)[""']\s*:\s*[""'][^""']*(curl|wget|powershell|pwsh|bash|sh|node\s+-e|python\s+-c)",
        RegexOptions.Compiled);

    private static readonly Regex PrivilegedContainer = new(
        @"(?im)(--privileged|privileged:\s*true|USER\s+root|curl\s+.*\|\s*(sh|bash)|wget\s+.*\|\s*(sh|bash))",
        RegexOptions.Compiled);

    private static readonly Regex BroadDependency = new(
        @"(?im)(version\s*=\s*[""']?\*|[""']latest[""']|\bhttp://|\*[""']?\s*[,}])",
        RegexOptions.Compiled);

    private static readonly Regex PrivacyRisk = new(
        @"(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie|session|jwt|aadhaar|ssn|credit[_-]?card|patient|student[_-]?record)",
        RegexOptions.Compiled);

    private static readonly HashSet<string> TextExtensions = new(
        [
            ".bat", ".cmd", ".config", ".cs", ".csproj", ".env", ".go",
            ".java", ".js", ".json", ".jsx", ".lock", ".md", ".php", ".ps1", ".psd1",
            ".psm1", ".py", ".sh", ".sql", ".ts", ".tsx", ".txt", ".xml",
            ".yaml", ".yml"
        ],
        StringComparer.OrdinalIgnoreCase);

    private static readonly HashSet<string> ExecutableExtensions = new(
        [".exe", ".dll", ".msi", ".scr", ".sys", ".ps1", ".bat", ".cmd", ".vbs"],
        StringComparer.OrdinalIgnoreCase);

    public CodeGateScanResult Evaluate(CodeGateScanRequest request)
    {
        var source = request.Source ?? "";
        var findings = EvaluateText(
            source,
            string.IsNullOrWhiteSpace(request.ImportPath)
                ? "inline"
                : request.ImportPath,
            0);
        var risk = findings.Sum(item => item.RiskScore);

        if (string.IsNullOrWhiteSpace(source))
        {
            var notEvaluated = Result(
                "not-evaluated",
                0,
                ["No source content was supplied for evaluation."]);
            SaveInlineSubmission(request, notEvaluated);
            return notEvaluated;
        }

        if (source.Length > 50_000)
        {
            findings.Add(CreateFinding(
                "CG-SIZE-001",
                "Info",
                10,
                request.ImportPath,
                "large-inline-submission",
                "Large submission; review with repository-scoped tooling before approval."));
            risk += 10;
        }

        risk = Math.Clamp(risk, 0, 100);
        if (findings.Count == 0)
        {
            var clean = Result("allow", 0, ["No local CodeGate rule matched."]);
            SaveInlineSubmission(request, clean);
            return clean;
        }

        var verdict = risk >= 80
            ? "block"
            : risk >= 30
                ? "warn"
                : "allow";
        var result = Result(
            verdict,
            risk,
            findings.Select(item => item.Explanation).ToList());
        SaveInlineSubmission(request, result);
        return result;
    }

    public CodeGateSubmissionDto ScanPath(
        CodeGatePathScanRequest request,
        string actor)
    {
        var path = Path.GetFullPath(request.Path ?? "");
        if (!File.Exists(path) && !Directory.Exists(path))
        {
            var missing = CreateSubmission(
                actor,
                request.Source,
                request.Revision,
                path,
                "not_evaluated",
                0,
                0,
                "",
                [
                    CreateFinding(
                        "CG-PATH-001",
                        "Medium",
                        30,
                        path,
                        "path-not-found",
                        "CodeGate path does not exist on this machine.")
                ]);
            repository?.SaveSubmission(missing);
            return missing;
        }

        var files = EnumerateFiles(path).Take(MaxFiles).ToList();
        var findings = new List<CodeGateFindingDto>();
        var hashInput = new StringBuilder();
        foreach (var file in files)
        {
            var info = new FileInfo(file);
            var relative = Path.GetRelativePath(path, file);
            if (File.Exists(path))
            {
                relative = Path.GetFileName(path);
            }

            var fileHash = HashFile(file);
            hashInput.Append(relative).Append('|').Append(fileHash).AppendLine();
            if (ExecutableExtensions.Contains(info.Extension))
            {
                findings.Add(CreateFinding(
                    "CG-FILE-001",
                    info.Extension.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
                    info.Extension.Equals(".dll", StringComparison.OrdinalIgnoreCase)
                        ? "High"
                        : "Medium",
                    info.Extension.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
                    info.Extension.Equals(".dll", StringComparison.OrdinalIgnoreCase)
                        ? 70
                        : 45,
                    relative,
                    info.Extension,
                    "Executable or script file requires review before trust."));
            }

            if (!TextExtensions.Contains(info.Extension) ||
                info.Length > MaxTextBytesPerFile)
            {
                continue;
            }

            var text = File.ReadAllText(file);
            findings.AddRange(EvaluateText(text, relative, findings.Count));
        }

        var risk = Math.Clamp(findings.Sum(item => item.RiskScore), 0, 100);
        var verdict = risk >= 80
            ? "block"
            : risk >= 30
                ? "warn"
                : "allow";
        var submission = CreateSubmission(
            actor,
            request.Source,
            request.Revision,
            path,
            verdict,
            risk,
            files.Count,
            Sha256(hashInput.ToString()),
            findings);
        repository?.SaveSubmission(submission);
        return submission;
    }

    public IReadOnlyList<CodeGateSubmissionDto> GetRecentSubmissions(
        int limit) =>
        repository?.GetRecentSubmissions(limit) ?? [];

    public CodeGateSubmissionDto? GetSubmission(string submissionId) =>
        repository?.GetSubmission(submissionId);

    public CodeGateGitPushAuditDto RecordGitPush(
        CodeGateGitPushRequest request,
        string actor)
    {
        var scanPath = string.IsNullOrWhiteSpace(request.ScanPath)
            ? request.RepositoryPath
            : request.ScanPath;
        var revision = string.IsNullOrWhiteSpace(request.NewRevision)
            ? request.Branch
            : request.NewRevision;
        var submission = ScanPath(
            new CodeGatePathScanRequest(
                scanPath,
                "git-push",
                revision),
            actor);
        var repositoryName = string.IsNullOrWhiteSpace(request.RepositoryName)
            ? Path.GetFileName(
                request.RepositoryPath.TrimEnd(
                    Path.DirectorySeparatorChar,
                    Path.AltDirectorySeparatorChar))
            : request.RepositoryName;
        var branch = string.IsNullOrWhiteSpace(request.Branch)
            ? ExtractBranch(request.RefName)
            : request.Branch;
        var audit = new CodeGateGitPushAuditDto(
            Guid.NewGuid().ToString("N"),
            DateTimeOffset.UtcNow,
            string.IsNullOrWhiteSpace(actor) ? "local-user" : actor,
            request.RepositoryPath ?? "",
            repositoryName,
            request.RefName ?? "",
            branch,
            request.OldRevision ?? "",
            request.NewRevision ?? "",
            submission.SubmissionId,
            submission.Verdict,
            submission.RiskScore,
            (request.ChangedFiles ?? [])
                .Where(file => !string.IsNullOrWhiteSpace(file))
                .Take(1000)
                .ToList());
        gitAudit?.Save(audit);
        return audit;
    }

    public IReadOnlyList<CodeGateGitPushAuditDto> GetRecentGitPushes(
        int limit) =>
        gitAudit?.GetRecent(limit) ?? [];

    public CodeGateGitPushAuditDto? GetGitPush(string auditId) =>
        gitAudit?.Get(auditId);

    public IReadOnlyList<CodeGateActiveRuleDto> GetActiveRules() =>
        activeRules?.GetActiveRules() ?? [];

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, Regex?> RuleRegexCache = new();

    private List<CodeGateFindingDto> EvaluateText(
        string source,
        string path,
        int offset)
    {
        var findings = new List<CodeGateFindingDto>();
        if (source.Contains(
                "-----BEGIN PRIVATE KEY-----",
                StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(CreateFinding(
                "CG-SECRET-001",
                "Critical",
                100,
                path,
                "-----BEGIN [REDACTED] KEY-----",
                "Private key material is present."));
        }

        if (AssignmentSecret.IsMatch(source) || CloudKey.IsMatch(source))
        {
            findings.Add(CreateFinding(
                "CG-SECRET-002",
                "Critical",
                90,
                path,
                RedactSecretEvidence(source),
                "Potential hardcoded credential or access token."));
        }

        if (EncodedExecution.IsMatch(source))
        {
            findings.Add(CreateFinding(
                "CG-SCRIPT-001",
                "Medium",
                45,
                path,
                "script-execution-pattern",
                "Suspicious script execution or remote download pattern."));
        }

        if (DestructiveDeploymentCommand.IsMatch(source))
        {
            findings.Add(CreateFinding(
                "CG-DEPLOY-001",
                "High",
                75,
                path,
                "destructive-deployment-command",
                "Deployment artifact contains destructive system or filesystem command."));
        }

        if (RemoteInstallerPipe.IsMatch(source))
        {
            findings.Add(CreateFinding(
                "CG-DEPLOY-002",
                "High",
                80,
                path,
                "remote-installer-pipe",
                "Deployment artifact pipes downloaded content into a shell."));
        }

        if (PackageLifecycleScript.IsMatch(source))
        {
            findings.Add(CreateFinding(
                "CG-DEPENDENCY-002",
                "High",
                75,
                path,
                "package-lifecycle-execution",
                "Package manifest runs network or shell commands during install lifecycle."));
        }

        if (LooksLikeContainerOrDeploymentFile(path) &&
            PrivilegedContainer.IsMatch(source))
        {
            findings.Add(CreateFinding(
                "CG-DEPLOY-003",
                "Medium",
                45,
                path,
                "privileged-container-or-root-runtime",
                "Deployment configuration uses privileged or root execution that requires review."));
        }

        if (BroadDependency.IsMatch(source))
        {
            findings.Add(CreateFinding(
                "CG-DEPENDENCY-001",
                "Low",
                25,
                path,
                "unpinned-or-insecure-dependency",
                "Dependency or URL pattern should be pinned and reviewed."));
        }

        if (LooksLikeDeploymentArtifact(path) && PrivacyRisk.IsMatch(source))
        {
            findings.Add(CreateFinding(
                "CG-PRIVACY-001",
                "Medium",
                40,
                path,
                "sensitive-data-or-credential-field",
                "Deployment artifact references sensitive data or credential fields; verify it is not exposing secrets or regulated data."));
        }

        if (activeRules is not null)
        {
            var dynamicRules = activeRules.GetActiveRules();
            foreach (var rule in dynamicRules)
            {
                if (!rule.Enabled || string.IsNullOrWhiteSpace(rule.Pattern))
                {
                    continue;
                }

                var regex = RuleRegexCache.GetOrAdd(rule.Pattern, pattern =>
                {
                    try
                    {
                        return new Regex(
                            pattern,
                            RegexOptions.Compiled | RegexOptions.IgnoreCase,
                            TimeSpan.FromSeconds(1));
                    }
                    catch
                    {
                        return null;
                    }
                });

                if (regex is not null)
                {
                    try
                    {
                        if (regex.IsMatch(source))
                        {
                            findings.Add(CreateFinding(
                                rule.RuleId,
                                rule.Severity,
                                rule.RiskScore,
                                path,
                                $"[RULE-MATCH] {rule.Name}",
                                rule.Explanation));
                        }
                    }
                    catch (RegexMatchTimeoutException)
                    {
                        // Ignore pattern match timeout
                    }
                }
            }
        }

        return findings
            .Select((finding, index) => finding with
            {
                FindingId = $"{finding.FindingId}-{offset + index + 1}"
            })
            .ToList();
    }

    private static CodeGateScanResult Result(
        string verdict,
        int risk,
        IReadOnlyList<string> findings) =>
        new(verdict, risk, findings, DateTimeOffset.UtcNow);

    private void SaveInlineSubmission(
        CodeGateScanRequest request,
        CodeGateScanResult result)
    {
        if (repository is null)
        {
            return;
        }

        repository.SaveSubmission(CreateSubmission(
            "local-api",
            "inline-content",
            request.Revision,
            request.ImportPath,
            result.Verdict,
            result.RiskScore,
            string.IsNullOrWhiteSpace(request.Source) ? 0 : 1,
            Sha256(request.Source ?? ""),
            result.Findings.Select((finding, index) => new CodeGateFindingDto(
                $"cgf-{Guid.NewGuid():N}",
                result.Verdict == "allow" ? "CG-CLEAN-001" : "CG-CONTENT-001",
                result.RiskScore >= 80 ? "Critical" :
                    result.RiskScore >= 30 ? "Medium" : "Info",
                result.RiskScore,
                request.ImportPath,
                "[REDACTED]",
                finding)).ToList()));
    }

    private static CodeGateSubmissionDto CreateSubmission(
        string actor,
        string source,
        string revision,
        string path,
        string verdict,
        int risk,
        int fileCount,
        string contentHash,
        IReadOnlyList<CodeGateFindingDto> findings)
    {
        var now = DateTimeOffset.UtcNow;
        return new(
            Guid.NewGuid().ToString("N"),
            now,
            string.IsNullOrWhiteSpace(actor) ? "local-user" : actor,
            string.IsNullOrWhiteSpace(source) ? "manual-scan" : source,
            revision ?? "",
            path,
            verdict,
            risk,
            fileCount,
            contentHash,
            findings);
    }

    private static CodeGateFindingDto CreateFinding(
        string ruleId,
        string severity,
        int risk,
        string path,
        string evidence,
        string explanation) =>
        new(
            $"cgf-{Guid.NewGuid():N}",
            ruleId,
            severity,
            risk,
            path ?? "",
            evidence,
            explanation);

    private static IEnumerable<string> EnumerateFiles(string path)
    {
        if (File.Exists(path))
        {
            yield return path;
            yield break;
        }

        var options = new EnumerationOptions
        {
            IgnoreInaccessible = true,
            RecurseSubdirectories = true,
            AttributesToSkip = FileAttributes.ReparsePoint
        };
        foreach (var file in Directory.EnumerateFiles(path, "*", options))
        {
            yield return file;
        }
    }

    private static string HashFile(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    private static string Sha256(string value) =>
        Convert.ToHexString(SHA256.HashData(
            Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static string RedactSecretEvidence(string source)
    {
        var match = AssignmentSecret.Match(source);
        if (match.Success)
        {
            var value = match.Value;
            var separator = value.Contains('=') ? '=' : ':';
            var left = value.Split(separator)[0].Trim();
            return $"{left}{separator} \"[REDACTED]\"";
        }

        match = CloudKey.Match(source);
        return match.Success
            ? $"{match.Value[..Math.Min(4, match.Value.Length)]}[REDACTED]"
            : "[REDACTED]";
    }

    private static string ExtractBranch(string refName) =>
        refName.StartsWith("refs/heads/", StringComparison.OrdinalIgnoreCase)
            ? refName["refs/heads/".Length..]
            : refName;

    private static bool LooksLikeDeploymentArtifact(string path)
    {
        var file = Path.GetFileName(path);
        return file.Contains("deploy", StringComparison.OrdinalIgnoreCase) ||
            file.Contains("docker", StringComparison.OrdinalIgnoreCase) ||
            file.Equals("package.json", StringComparison.OrdinalIgnoreCase) ||
            file.Equals("composer.json", StringComparison.OrdinalIgnoreCase) ||
            file.Equals("requirements.txt", StringComparison.OrdinalIgnoreCase) ||
            file.Equals(".env", StringComparison.OrdinalIgnoreCase) ||
            path.Contains("k8s", StringComparison.OrdinalIgnoreCase) ||
            path.Contains("helm", StringComparison.OrdinalIgnoreCase);
    }

    private static bool LooksLikeContainerOrDeploymentFile(string path)
    {
        var file = Path.GetFileName(path);
        return file.Contains("docker", StringComparison.OrdinalIgnoreCase) ||
            file.Contains("compose", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(".yml", StringComparison.OrdinalIgnoreCase);
    }
}
