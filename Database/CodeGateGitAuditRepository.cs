using System.Text.Json;
using Microsoft.Data.Sqlite;
using RoamSentinel.Core;

namespace RoamSentinel.Database;

public sealed class CodeGateGitAuditRepository(
    IDatabaseConnectionFactory connections) : ICodeGateGitAuditRepository
{
    public void Save(CodeGateGitPushAuditDto audit)
    {
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO codegate_git_pushes(
                audit_id, observed_at, actor, repository_path, repository_name,
                ref_name, branch, old_revision, new_revision, submission_id,
                verdict, risk_score)
            VALUES(
                $id, $observedAt, $actor, $repositoryPath, $repositoryName,
                $refName, $branch, $oldRevision, $newRevision, $submissionId,
                $verdict, $riskScore);
            """;
        command.Parameters.AddWithValue("$id", audit.AuditId);
        command.Parameters.AddWithValue("$observedAt", audit.ObservedAt.ToString("O"));
        command.Parameters.AddWithValue("$actor", audit.Actor);
        command.Parameters.AddWithValue("$repositoryPath", audit.RepositoryPath);
        command.Parameters.AddWithValue("$repositoryName", audit.RepositoryName);
        command.Parameters.AddWithValue("$refName", audit.RefName);
        command.Parameters.AddWithValue("$branch", audit.Branch);
        command.Parameters.AddWithValue("$oldRevision", audit.OldRevision);
        command.Parameters.AddWithValue("$newRevision", audit.NewRevision);
        command.Parameters.AddWithValue("$submissionId", audit.SubmissionId);
        command.Parameters.AddWithValue("$verdict", audit.Verdict);
        command.Parameters.AddWithValue("$riskScore", audit.RiskScore);
        command.ExecuteNonQuery();

        var ordinal = 0;
        foreach (var file in audit.ChangedFiles.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            using var fileCommand = connection.CreateCommand();
            fileCommand.Transaction = transaction;
            fileCommand.CommandText = """
                INSERT INTO codegate_git_push_files(audit_id, file_path, ordinal)
                VALUES($auditId, $filePath, $ordinal);
                """;
            fileCommand.Parameters.AddWithValue("$auditId", audit.AuditId);
            fileCommand.Parameters.AddWithValue("$filePath", file);
            fileCommand.Parameters.AddWithValue("$ordinal", ordinal++);
            fileCommand.ExecuteNonQuery();
        }

        AuditSql.Insert(
            connection,
            transaction,
            audit.Actor,
            "codegate.git_push_recorded",
            "codegate_git_push",
            audit.AuditId,
            true,
            JsonSerializer.Serialize(new
            {
                audit.RepositoryName,
                audit.Branch,
                audit.NewRevision,
                audit.Verdict,
                audit.RiskScore,
                Files = audit.ChangedFiles.Count
            }));
        transaction.Commit();
    }

    public IReadOnlyList<CodeGateGitPushAuditDto> GetRecent(int limit)
    {
        using var connection = connections.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT audit_id, observed_at, actor, repository_path, repository_name,
                   ref_name, branch, old_revision, new_revision, submission_id,
                   verdict, risk_score
            FROM codegate_git_pushes
            ORDER BY observed_at DESC
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 1000));
        using var reader = command.ExecuteReader();
        var result = new List<CodeGateGitPushAuditDto>();
        while (reader.Read())
        {
            var auditId = reader.GetString(0);
            result.Add(new(
                auditId,
                DateTimeOffset.Parse(reader.GetString(1)),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetString(4),
                reader.GetString(5),
                reader.GetString(6),
                reader.GetString(7),
                reader.GetString(8),
                reader.GetString(9),
                reader.GetString(10),
                reader.GetInt32(11),
                ReadFiles(connection, auditId)));
        }

        return result;
    }

    public CodeGateGitPushAuditDto? Get(string auditId)
    {
        using var connection = connections.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT audit_id, observed_at, actor, repository_path, repository_name,
                   ref_name, branch, old_revision, new_revision, submission_id,
                   verdict, risk_score
            FROM codegate_git_pushes
            WHERE audit_id=$auditId;
            """;
        command.Parameters.AddWithValue("$auditId", auditId);
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
            reader.GetString(7),
            reader.GetString(8),
            reader.GetString(9),
            reader.GetString(10),
            reader.GetInt32(11),
            ReadFiles(connection, auditId));
    }

    private static IReadOnlyList<string> ReadFiles(
        SqliteConnection connection,
        string auditId)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT file_path
            FROM codegate_git_push_files
            WHERE audit_id=$auditId
            ORDER BY ordinal, file_path;
            """;
        command.Parameters.AddWithValue("$auditId", auditId);
        using var reader = command.ExecuteReader();
        var files = new List<string>();
        while (reader.Read())
        {
            files.Add(reader.GetString(0));
        }

        return files;
    }
}
