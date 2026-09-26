using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using RoamSentinel.Core;

namespace RoamSentinel.Database;

public sealed class BackupExportService(
    IDatabaseConnectionFactory connections,
    IDatabaseStatusRepository databaseStatus,
    IAuditRepository audit,
    IStructuredLogService logs) : IBackupExportService
{
    public BackupExportDto Create(string actor)
    {
        var exportedAt = DateTimeOffset.UtcNow;
        var exportId = Guid.NewGuid().ToString("N");
        var temporaryPath = Path.Combine(
            Path.GetTempPath(),
            $"roamsentinel-{exportId}.db");

        try
        {
            CreateConsistentDatabaseCopy(temporaryPath);
            var status = databaseStatus.GetStatus();
            var databaseSha256 = GetSha256(temporaryPath);
            using var output = new MemoryStream();
            using (var archive = new ZipArchive(
                       output,
                       ZipArchiveMode.Create,
                       leaveOpen: true))
            {
                AddFile(archive, "roamsentinel.db", temporaryPath);
                AddText(
                    archive,
                    "manifest.json",
                    JsonSerializer.Serialize(
                        new
                        {
                            product = ProductInfo.Name,
                            version = ProductInfo.Version,
                            exportedAt,
                            machine = Environment.MachineName,
                            databaseProvider = status.Provider,
                            latestMigration = status.LatestMigration,
                            appliedMigrationCount =
                                status.AppliedMigrationCount,
                            databaseSha256,
                            containsSecrets = false
                        },
                        new JsonSerializerOptions { WriteIndented = true }));
                AddText(
                    archive,
                    "RESTORE.txt",
                    """
                    RoamSentinel backup

                    1. Stop RoamSentinel.
                    2. Run RoamSentinel.exe --restore-backup <backup.zip>, or use the authenticated restore API.
                    3. Start RoamSentinel and review Database Status and Audit Log.

                    Access tokens and threat-intelligence API keys are not included.
                    """);
            }

            var fileName =
                $"RoamSentinel-backup-{exportedAt:yyyyMMdd-HHmmss}.zip";
            audit.Write(
                actor,
                "backup.exported",
                "database",
                exportId,
                true,
                JsonSerializer.Serialize(new
                {
                    FileName = fileName,
                    status.LatestMigration
                }));
            logs.Security(
                "backup.exported",
                "Administrator exported a database backup.",
                new
                {
                    Actor = actor,
                    ExportId = exportId,
                    FileName = fileName
                });
            return new BackupExportDto(
                fileName,
                "application/zip",
                output.ToArray());
        }
        catch (Exception exception)
        {
            audit.Write(
                actor,
                "backup.exported",
                "database",
                exportId,
                false,
                JsonSerializer.Serialize(new
                {
                    Error = exception.Message
                }));
            logs.Error(
                "backup.export.failed",
                exception,
                new { Actor = actor, ExportId = exportId });
            throw;
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    public BackupRestoreDto Restore(Stream archiveStream, string actor)
    {
        const long maximumDatabaseBytes = 1024L * 1024L * 1024L;
        var restoreId = Guid.NewGuid().ToString("N");
        var temporaryPath = Path.Combine(
            Path.GetTempPath(),
            $"roamsentinel-restore-{restoreId}.db");
        var safetyCopy = $"{connections.DatabasePath}.before-restore-{DateTime.UtcNow:yyyyMMddHHmmss}";

        try
        {
            using var archive = new ZipArchive(
                archiveStream,
                ZipArchiveMode.Read,
                leaveOpen: true);
            var databaseEntry = archive.GetEntry("roamsentinel.db")
                ?? throw new InvalidDataException(
                    "Backup does not contain roamsentinel.db.");
            var manifestEntry = archive.GetEntry("manifest.json")
                ?? throw new InvalidDataException(
                    "Backup does not contain manifest.json.");
            if (databaseEntry.Length <= 0 ||
                databaseEntry.Length > maximumDatabaseBytes)
            {
                throw new InvalidDataException(
                    "Backup database size is invalid.");
            }

            using var manifest = JsonDocument.Parse(manifestEntry.Open());
            var root = manifest.RootElement;
            var product = root.GetProperty("product").GetString();
            if (!string.Equals(product, ProductInfo.Name, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Backup product identity is invalid.");
            }

            var expectedHash = root.GetProperty("databaseSha256").GetString();
            using (var input = databaseEntry.Open())
            using (var output = new FileStream(
                       temporaryPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None))
            {
                input.CopyTo(output);
            }

            var actualHash = GetSha256(temporaryPath);
            if (string.IsNullOrWhiteSpace(expectedHash) ||
                !CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(expectedHash),
                    Convert.FromHexString(actualHash)))
            {
                throw new InvalidDataException(
                    "Backup database checksum validation failed.");
            }

            ValidateSqliteIntegrity(temporaryPath);
            audit.Write(
                actor,
                "backup.restore.requested",
                "database",
                restoreId,
                true,
                JsonSerializer.Serialize(new { Sha256 = actualHash }));

            SqliteConnection.ClearAllPools();
            if (File.Exists(connections.DatabasePath))
            {
                File.Copy(connections.DatabasePath, safetyCopy, overwrite: false);
            }

            File.Move(temporaryPath, connections.DatabasePath, overwrite: true);
            logs.Security(
                "backup.restored",
                "Administrator restored a validated database backup.",
                new { Actor = actor, RestoreId = restoreId, Sha256 = actualHash });
            return new BackupRestoreDto(
                true,
                "Backup integrity validated and database restored.",
                actualHash,
                File.Exists(safetyCopy) ? safetyCopy : "");
        }
        catch (Exception exception)
        {
            audit.Write(
                actor,
                "backup.restore.failed",
                "database",
                restoreId,
                false,
                JsonSerializer.Serialize(new { Error = exception.Message }));
            logs.Error(
                "backup.restore.failed",
                exception,
                new { Actor = actor, RestoreId = restoreId });
            throw;
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private void CreateConsistentDatabaseCopy(string path)
    {
        using var source = connections.OpenConnection();
        using var destination = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = path,
                Mode = SqliteOpenMode.ReadWriteCreate,
                Pooling = false
            }.ToString());
        destination.Open();
        source.BackupDatabase(destination);
    }

    private static void AddFile(
        ZipArchive archive,
        string entryName,
        string sourcePath)
    {
        var entry = archive.CreateEntry(
            entryName,
            CompressionLevel.Optimal);
        using var destination = entry.Open();
        using var source = File.OpenRead(sourcePath);
        source.CopyTo(destination);
    }

    private static void AddText(
        ZipArchive archive,
        string entryName,
        string content)
    {
        var entry = archive.CreateEntry(
            entryName,
            CompressionLevel.Optimal);
        using var writer = new StreamWriter(
            entry.Open(),
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        writer.Write(content);
    }

    private static string GetSha256(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static void ValidateSqliteIntegrity(string path)
    {
        using var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = path,
                Mode = SqliteOpenMode.ReadOnly,
                Pooling = false
            }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA integrity_check;";
        var result = Convert.ToString(command.ExecuteScalar());
        if (!string.Equals(result, "ok", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"SQLite integrity validation failed: {result}");
        }
    }
}
