using RoamSentinel.Core;
using RoamSentinel.App.Security;
using System.Text;

namespace RoamSentinel.App.Api;

public static class ModuleEndpoints
{
    public static IEndpointRouteBuilder MapModuleEndpoints(
        this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet(
            "/api/modules",
            (IEnumerable<IProductModule> modules) =>
                Results.Ok(modules.Select(module => module.Registration)));
        endpoints.MapGet(
            "/api/v1/module-experiences",
            (IModuleExperienceService experiences) =>
                Results.Ok(experiences.GetManifest()));
        endpoints.MapGet(
            "/api/modules/insider-risk",
            (IInsiderRiskService insiderRisk) =>
                Results.Ok(insiderRisk.GetSummary()));
        endpoints.MapGet(
            "/api/v1/device-shield/personal-protection",
            (IPersonalProtectionProfileService profile) =>
                Results.Ok(profile.GetProfile()));
        endpoints.MapGet(
            "/api/v1/scheduler",
            (IProtectionSchedulerExperienceService scheduler) =>
                Results.Ok(scheduler.GetDashboard()));
        endpoints.MapPost(
            "/api/modules/codegate/scan",
            ScanCodeAsync);
        endpoints.MapPost(
            "/api/v1/codegate/scan-path",
            ScanPathAsync);
        endpoints.MapGet(
            "/api/v1/codegate/submissions",
            (ICodeGateService codeGate, int? limit) =>
                Results.Ok(codeGate.GetRecentSubmissions(
                    Math.Clamp(limit ?? 100, 1, 500))));
        endpoints.MapGet(
            "/api/v1/codegate/submissions/{submissionId}",
            GetSubmissionAsync);
        endpoints.MapPost(
            "/api/v1/codegate/git-push",
            RecordGitPushAsync);
        endpoints.MapGet(
            "/api/v1/codegate/git-pushes",
            (ICodeGateService codeGate, int? limit) =>
                Results.Ok(codeGate.GetRecentGitPushes(
                    Math.Clamp(limit ?? 100, 1, 500))));
        endpoints.MapGet(
            "/api/v1/codegate/git-pushes/{auditId}",
            GetGitPushAsync);
        endpoints.MapPost(
            "/api/v1/codegate/offline-bundles/import",
            ImportOfflineBundleAsync);
        endpoints.MapGet(
            "/api/v1/codegate/offline-bundles",
            (ICodeGateBundleService bundles, int? limit) =>
                Results.Ok(bundles.GetRecentBundles(
                    Math.Clamp(limit ?? 100, 1, 500))));
        endpoints.MapGet(
            "/api/v1/codegate/rules",
            (ICodeGateService codeGate) =>
                Results.Ok(codeGate.GetActiveRules()));
        endpoints.MapGet(
            "/api/v1/codegate/reports/submissions.csv",
            ExportSubmissionsCsv);
        endpoints.MapGet(
            "/api/v1/codegate/reports/git-pushes.csv",
            ExportGitPushesCsv);
        endpoints.MapGet(
            "/api/v1/codegate/reports/offline-bundles.csv",
            ExportBundlesCsv);
        return endpoints;
    }

    private static IResult ScanCodeAsync(
        CodeGateScanRequest request,
        ICodeGateService codeGate,
        ILocalSessionService sessions,
        HttpContext context)
    {
        var denied = EndpointSecurity.RequireRole(
            context,
            sessions,
            "Analyst");
        if (denied is not null)
        {
            return denied;
        }

        if ((request.Source?.Length ?? 0) > 150_000 ||
            (request.Revision?.Length ?? 0) > 128 ||
            (request.ImportPath?.Length ?? 0) > 512)
        {
            return Results.BadRequest(new
            {
                error = "CodeGate input is outside the accepted size limit."
            });
        }

        return Results.Ok(codeGate.Evaluate(request));
    }

    private static IResult ScanPathAsync(
        CodeGatePathScanRequest request,
        ICodeGateService codeGate,
        ILocalSessionService sessions,
        HttpContext context)
    {
        var denied = EndpointSecurity.RequireRole(
            context,
            sessions,
            "Analyst");
        if (denied is not null)
        {
            return denied;
        }

        if (string.IsNullOrWhiteSpace(request.Path) ||
            request.Path.Length > 512 ||
            (request.Source?.Length ?? 0) > 64 ||
            (request.Revision?.Length ?? 0) > 128)
        {
            return Results.BadRequest(new
            {
                error = "CodeGate path scan input is invalid."
            });
        }

        var session = sessions.Resolve(context.Request);
        return Results.Ok(codeGate.ScanPath(
            request,
            session?.Role ?? "local-user"));
    }

    private static IResult RecordGitPushAsync(
        CodeGateGitPushRequest request,
        ICodeGateService codeGate,
        ILocalSessionService sessions,
        HttpContext context)
    {
        var denied = EndpointSecurity.RequireRole(
            context,
            sessions,
            "Analyst");
        if (denied is not null)
        {
            return denied;
        }

        if (string.IsNullOrWhiteSpace(request.RepositoryPath) ||
            request.RepositoryPath.Length > 512 ||
            (request.ScanPath?.Length ?? 0) > 512 ||
            (request.RefName?.Length ?? 0) > 256 ||
            (request.Branch?.Length ?? 0) > 256 ||
            (request.OldRevision?.Length ?? 0) > 128 ||
            (request.NewRevision?.Length ?? 0) > 128 ||
            (request.ChangedFiles?.Count ?? 0) > 1000)
        {
            return Results.BadRequest(new
            {
                error = "CodeGate git push audit input is invalid."
            });
        }

        var session = sessions.Resolve(context.Request);
        return Results.Ok(codeGate.RecordGitPush(
            request,
            session?.Role ?? "local-user"));
    }

    private static IResult GetSubmissionAsync(
        string submissionId,
        ICodeGateService codeGate,
        ILocalSessionService sessions,
        HttpContext context)
    {
        var denied = EndpointSecurity.RequireRole(
            context,
            sessions,
            "Analyst");
        if (denied is not null)
        {
            return denied;
        }

        if (!IsSafeIdentifier(submissionId))
        {
            return Results.BadRequest(new
            {
                error = "CodeGate submission identifier is invalid."
            });
        }

        var submission = codeGate.GetSubmission(submissionId);
        return submission is null
            ? Results.NotFound(new { error = "CodeGate submission was not found." })
            : Results.Ok(submission);
    }

    private static IResult GetGitPushAsync(
        string auditId,
        ICodeGateService codeGate,
        ILocalSessionService sessions,
        HttpContext context)
    {
        var denied = EndpointSecurity.RequireRole(
            context,
            sessions,
            "Analyst");
        if (denied is not null)
        {
            return denied;
        }

        if (!IsSafeIdentifier(auditId))
        {
            return Results.BadRequest(new
            {
                error = "CodeGate git push audit identifier is invalid."
            });
        }

        var audit = codeGate.GetGitPush(auditId);
        return audit is null
            ? Results.NotFound(new { error = "CodeGate git push audit was not found." })
            : Results.Ok(audit);
    }

    private static IResult ImportOfflineBundleAsync(
        CodeGateBundleImportRequest request,
        ICodeGateBundleService bundles,
        ILocalSessionService sessions,
        HttpContext context)
    {
        var denied = EndpointSecurity.RequireRole(
            context,
            sessions,
            "Administrator");
        if (denied is not null)
        {
            return denied;
        }

        if (string.IsNullOrWhiteSpace(request.Path) ||
            request.Path.Length > 512 ||
            (request.ExpectedSha256?.Length ?? 0) > 128)
        {
            return Results.BadRequest(new
            {
                error = "Offline bundle import input is invalid."
            });
        }

        try
        {
            var session = sessions.Resolve(context.Request);
            return Results.Ok(bundles.ImportBundle(
                request,
                session?.Role ?? "local-user"));
        }
        catch (Exception exception) when (
            exception is ArgumentException or IOException or InvalidDataException
                or System.Text.Json.JsonException)
        {
            return Results.BadRequest(new { error = exception.Message });
        }
    }

    private static IResult ExportSubmissionsCsv(
        ICodeGateService codeGate,
        ILocalSessionService sessions,
        HttpContext context,
        string? verdict,
        string? source,
        int? limit)
    {
        var denied = EndpointSecurity.RequireRole(
            context,
            sessions,
            "Analyst");
        if (denied is not null)
        {
            return denied;
        }

        var rows = codeGate.GetRecentSubmissions(Math.Clamp(limit ?? 1000, 1, 5000))
            .Where(row => Matches(row.Verdict, verdict))
            .Where(row => Matches(row.Source, source))
            .ToList();
        var csv = Csv(
            ["submission_id", "evaluated_at", "actor", "source", "revision",
             "import_path", "verdict", "risk_score", "file_count",
             "content_sha256", "finding_count"],
            rows.Select(row => new[]
            {
                row.SubmissionId,
                row.EvaluatedAt.ToString("O"),
                row.Actor,
                row.Source,
                row.Revision,
                row.ImportPath,
                row.Verdict,
                row.RiskScore.ToString(),
                row.FileCount.ToString(),
                row.ContentSha256,
                row.Findings.Count.ToString()
            }));
        return CsvFile(csv, "roamsentinel-codegate-submissions.csv");
    }

    private static IResult ExportGitPushesCsv(
        ICodeGateService codeGate,
        ILocalSessionService sessions,
        HttpContext context,
        string? verdict,
        string? repository,
        string? branch,
        string? actor,
        int? limit)
    {
        var denied = EndpointSecurity.RequireRole(
            context,
            sessions,
            "Analyst");
        if (denied is not null)
        {
            return denied;
        }

        var rows = codeGate.GetRecentGitPushes(Math.Clamp(limit ?? 1000, 1, 5000))
            .Where(row => Matches(row.Verdict, verdict))
            .Where(row => Contains(row.RepositoryName, repository))
            .Where(row => Matches(row.Branch, branch))
            .Where(row => Contains(row.Actor, actor))
            .ToList();
        var csv = Csv(
            ["audit_id", "observed_at", "actor", "repository_name",
             "repository_path", "ref_name", "branch", "old_revision",
             "new_revision", "submission_id", "verdict", "risk_score",
             "changed_file_count", "changed_files"],
            rows.Select(row => new[]
            {
                row.AuditId,
                row.ObservedAt.ToString("O"),
                row.Actor,
                row.RepositoryName,
                row.RepositoryPath,
                row.RefName,
                row.Branch,
                row.OldRevision,
                row.NewRevision,
                row.SubmissionId,
                row.Verdict,
                row.RiskScore.ToString(),
                row.ChangedFiles.Count.ToString(),
                string.Join(";", row.ChangedFiles)
            }));
        return CsvFile(csv, "roamsentinel-codegate-git-pushes.csv");
    }

    private static IResult ExportBundlesCsv(
        ICodeGateBundleService bundles,
        ILocalSessionService sessions,
        HttpContext context,
        string? bundleType,
        string? status,
        int? limit)
    {
        var denied = EndpointSecurity.RequireRole(
            context,
            sessions,
            "Analyst");
        if (denied is not null)
        {
            return denied;
        }

        var rows = bundles.GetRecentBundles(Math.Clamp(limit ?? 1000, 1, 5000))
            .Where(row => Matches(row.BundleType, bundleType))
            .Where(row => Matches(row.Status, status))
            .ToList();
        var csv = Csv(
            ["bundle_id", "imported_at", "component", "bundle_type", "name",
             "version", "schema_version", "generated_at", "source", "sha256",
             "signature", "verified", "status", "message", "imported_by"],
            rows.Select(row => new[]
            {
                row.BundleId,
                row.ImportedAt.ToString("O"),
                row.Component,
                row.BundleType,
                row.Name,
                row.Version,
                row.SchemaVersion,
                row.GeneratedAt.ToString("O"),
                row.Source,
                row.Sha256,
                row.Signature,
                row.Verified.ToString(),
                row.Status,
                row.Message,
                row.ImportedBy
            }));
        return CsvFile(csv, "roamsentinel-codegate-offline-bundles.csv");
    }

    private static IResult CsvFile(string csv, string fileName) =>
        Results.File(
            Encoding.UTF8.GetBytes(csv),
            "text/csv; charset=utf-8",
            fileName);

    private static string Csv(
        IReadOnlyList<string> headers,
        IEnumerable<IReadOnlyList<string>> rows)
    {
        var builder = new StringBuilder();
        builder.AppendLine(string.Join(",", headers.Select(EscapeCsv)));
        foreach (var row in rows)
        {
            builder.AppendLine(string.Join(",", row.Select(EscapeCsv)));
        }

        return builder.ToString();
    }

    private static string EscapeCsv(string? value)
    {
        value ??= "";
        return value.Contains('"') ||
            value.Contains(',') ||
            value.Contains('\n') ||
            value.Contains('\r')
            ? $"\"{value.Replace("\"", "\"\"")}\""
            : value;
    }

    private static bool Matches(string value, string? filter) =>
        string.IsNullOrWhiteSpace(filter) ||
        value.Equals(filter, StringComparison.OrdinalIgnoreCase);

    private static bool Contains(string value, string? filter) =>
        string.IsNullOrWhiteSpace(filter) ||
        value.Contains(filter, StringComparison.OrdinalIgnoreCase);

    private static bool IsSafeIdentifier(string value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= 64 &&
        value.All(character =>
            char.IsLetterOrDigit(character) ||
            character is '-' or '_');
}
