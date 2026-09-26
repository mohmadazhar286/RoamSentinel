using System.Text.Json;
using Microsoft.Data.Sqlite;
using RoamSentinel.Core;

namespace RoamSentinel.Database;

public sealed class CodeGateBundleRepository(
    IDatabaseConnectionFactory connections) : ICodeGateBundleRepository
{
    public void Save(CodeGateBundleDto bundle)
    {
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO codegate_offline_bundles(
                bundle_id, imported_at, component, bundle_type, name, version,
                schema_version, generated_at, source, sha256, signature,
                verified, status, message, imported_by)
            VALUES(
                $id, $importedAt, $component, $type, $name, $version,
                $schema, $generatedAt, $source, $sha256, $signature,
                $verified, $status, $message, $actor)
            ON CONFLICT(sha256) DO UPDATE SET
                imported_at=excluded.imported_at,
                verified=excluded.verified,
                status=excluded.status,
                message=excluded.message,
                imported_by=excluded.imported_by;
            """;
        command.Parameters.AddWithValue("$id", bundle.BundleId);
        command.Parameters.AddWithValue("$importedAt", bundle.ImportedAt.ToString("O"));
        command.Parameters.AddWithValue("$component", bundle.Component);
        command.Parameters.AddWithValue("$type", bundle.BundleType);
        command.Parameters.AddWithValue("$name", bundle.Name);
        command.Parameters.AddWithValue("$version", bundle.Version);
        command.Parameters.AddWithValue("$schema", bundle.SchemaVersion);
        command.Parameters.AddWithValue("$generatedAt", bundle.GeneratedAt.ToString("O"));
        command.Parameters.AddWithValue("$source", bundle.Source);
        command.Parameters.AddWithValue("$sha256", bundle.Sha256);
        command.Parameters.AddWithValue("$signature", bundle.Signature);
        command.Parameters.AddWithValue("$verified", bundle.Verified ? 1 : 0);
        command.Parameters.AddWithValue("$status", bundle.Status);
        command.Parameters.AddWithValue("$message", bundle.Message);
        command.Parameters.AddWithValue("$actor", bundle.ImportedBy);
        command.ExecuteNonQuery();

        AuditSql.Insert(
            connection,
            transaction,
            bundle.ImportedBy,
            "codegate.offline_bundle_imported",
            "codegate_offline_bundle",
            bundle.BundleId,
            bundle.Verified,
            JsonSerializer.Serialize(new
            {
                bundle.Component,
                bundle.BundleType,
                bundle.Name,
                bundle.Version,
                bundle.SchemaVersion,
                bundle.Sha256,
                bundle.Status
            }));
        transaction.Commit();
    }

    public IReadOnlyList<CodeGateBundleDto> GetRecent(int limit)
    {
        using var connection = connections.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT bundle_id, imported_at, component, bundle_type, name,
                   version, schema_version, generated_at, source, sha256,
                   signature, verified, status, message, imported_by
            FROM codegate_offline_bundles
            ORDER BY imported_at DESC
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 1000));
        using var reader = command.ExecuteReader();
        var rows = new List<CodeGateBundleDto>();
        while (reader.Read())
        {
            rows.Add(new(
                reader.GetString(0),
                DateTimeOffset.Parse(reader.GetString(1)),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetString(4),
                reader.GetString(5),
                reader.GetString(6),
                DateTimeOffset.Parse(reader.GetString(7)),
                reader.GetString(8),
                reader.GetString(9),
                reader.GetString(10),
                reader.GetInt32(11) == 1,
                reader.GetString(12),
                reader.GetString(13),
                reader.GetString(14)));
        }

        return rows;
    }
}
