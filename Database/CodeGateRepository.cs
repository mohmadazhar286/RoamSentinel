using System.Text.Json;
using Microsoft.Data.Sqlite;
using RoamSentinel.Core;

namespace RoamSentinel.Database;

public sealed class CodeGateRepository(
    IDatabaseConnectionFactory connections) : ICodeGateRepository
{
    public void SaveSubmission(CodeGateSubmissionDto submission)
    {
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO codegate_submissions(
                submission_id, evaluated_at, actor, source, revision,
                import_path, verdict, risk_score, file_count, content_sha256)
            VALUES(
                $id, $evaluatedAt, $actor, $source, $revision,
                $path, $verdict, $risk, $files, $sha256)
            ON CONFLICT(submission_id) DO UPDATE SET
                evaluated_at=excluded.evaluated_at,
                actor=excluded.actor,
                source=excluded.source,
                revision=excluded.revision,
                import_path=excluded.import_path,
                verdict=excluded.verdict,
                risk_score=excluded.risk_score,
                file_count=excluded.file_count,
                content_sha256=excluded.content_sha256;
            """;
        command.Parameters.AddWithValue("$id", submission.SubmissionId);
        command.Parameters.AddWithValue(
            "$evaluatedAt",
            submission.EvaluatedAt.ToString("O"));
        command.Parameters.AddWithValue("$actor", submission.Actor);
        command.Parameters.AddWithValue("$source", submission.Source);
        command.Parameters.AddWithValue("$revision", submission.Revision);
        command.Parameters.AddWithValue("$path", submission.ImportPath);
        command.Parameters.AddWithValue("$verdict", NormalizeVerdict(submission.Verdict));
        command.Parameters.AddWithValue("$risk", submission.RiskScore);
        command.Parameters.AddWithValue("$files", submission.FileCount);
        command.Parameters.AddWithValue("$sha256", submission.ContentSha256);
        command.ExecuteNonQuery();

        using var delete = connection.CreateCommand();
        delete.Transaction = transaction;
        delete.CommandText =
            "DELETE FROM codegate_findings WHERE submission_id=$submission;";
        delete.Parameters.AddWithValue("$submission", submission.SubmissionId);
        delete.ExecuteNonQuery();

        foreach (var finding in submission.Findings)
        {
            InsertFinding(connection, transaction, submission.SubmissionId, finding);
        }

        AuditSql.Insert(
            connection,
            transaction,
            submission.Actor,
            "codegate.submission_recorded",
            "codegate_submission",
            submission.SubmissionId,
            true,
            JsonSerializer.Serialize(new
            {
                submission.Source,
                submission.Revision,
                submission.Verdict,
                submission.RiskScore,
                submission.FileCount,
                Findings = submission.Findings.Count
            }));
        transaction.Commit();
    }

    public IReadOnlyList<CodeGateSubmissionDto> GetRecentSubmissions(int limit)
    {
        using var connection = connections.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT submission_id, evaluated_at, actor, source, revision,
                   import_path, verdict, risk_score, file_count, content_sha256
            FROM codegate_submissions
            ORDER BY evaluated_at DESC
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 1000));
        using var reader = command.ExecuteReader();
        var submissions = new List<CodeGateSubmissionDto>();
        while (reader.Read())
        {
            var submissionId = reader.GetString(0);
            submissions.Add(new(
                submissionId,
                DateTimeOffset.Parse(reader.GetString(1)),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetString(4),
                reader.GetString(5),
                reader.GetString(6),
                reader.GetInt32(7),
                reader.GetInt32(8),
                reader.GetString(9),
                ReadFindings(connection, submissionId)));
        }

        return submissions;
    }

    public CodeGateSubmissionDto? GetSubmission(string submissionId)
    {
        using var connection = connections.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT submission_id, evaluated_at, actor, source, revision,
                   import_path, verdict, risk_score, file_count, content_sha256
            FROM codegate_submissions
            WHERE submission_id=$submission;
            """;
        command.Parameters.AddWithValue("$submission", submissionId);
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        return new(
            reader.GetString(0),
            DateTimeOffset.Parse(reader.GetString(1)),
            reader.GetString(2),
            reader.GetString(3),
            reader.GetString(4),
            reader.GetString(5),
            reader.GetString(6),
            reader.GetInt32(7),
            reader.GetInt32(8),
            reader.GetString(9),
            ReadFindings(connection, submissionId));
    }

    private static void InsertFinding(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string submissionId,
        CodeGateFindingDto finding)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO codegate_findings(
                finding_id, submission_id, rule_id, severity, risk_score,
                file_path, evidence, explanation)
            VALUES(
                $id, $submission, $rule, $severity, $risk,
                $path, $evidence, $explanation);
            """;
        command.Parameters.AddWithValue("$id", finding.FindingId);
        command.Parameters.AddWithValue("$submission", submissionId);
        command.Parameters.AddWithValue("$rule", finding.RuleId);
        command.Parameters.AddWithValue("$severity", finding.Severity);
        command.Parameters.AddWithValue("$risk", finding.RiskScore);
        command.Parameters.AddWithValue("$path", finding.FilePath);
        command.Parameters.AddWithValue("$evidence", finding.Evidence);
        command.Parameters.AddWithValue("$explanation", finding.Explanation);
        command.ExecuteNonQuery();
    }

    private static IReadOnlyList<CodeGateFindingDto> ReadFindings(
        SqliteConnection connection,
        string submissionId)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT finding_id, rule_id, severity, risk_score, file_path,
                   evidence, explanation
            FROM codegate_findings
            WHERE submission_id=$submission
            ORDER BY risk_score DESC, rule_id;
            """;
        command.Parameters.AddWithValue("$submission", submissionId);
        using var reader = command.ExecuteReader();
        var findings = new List<CodeGateFindingDto>();
        while (reader.Read())
        {
            findings.Add(new(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetInt32(3),
                reader.GetString(4),
                reader.GetString(5),
                reader.GetString(6)));
        }

        return findings;
    }

    private static string NormalizeVerdict(string verdict) =>
        string.Equals(verdict, "not-evaluated", StringComparison.OrdinalIgnoreCase)
            ? "not_evaluated"
            : verdict.ToLowerInvariant();
}
