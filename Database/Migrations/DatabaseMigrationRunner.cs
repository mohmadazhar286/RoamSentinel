using Microsoft.Data.Sqlite;

namespace RoamSentinel.Database.Migrations;

public sealed class DatabaseMigrationRunner(
    IDatabaseConnectionFactory connections,
    IEnumerable<IDatabaseMigration> migrations) : IDatabaseMigrationRunner
{
    public void Migrate()
    {
        using var connection = connections.OpenConnection();
        ConfigureDatabase(connection);
        EnsureMigrationTable(connection);

        var applied = GetAppliedVersions(connection);
        foreach (var migration in migrations.OrderBy(item => item.Version))
        {
            if (applied.Contains(migration.Version))
            {
                continue;
            }

            using var transaction = connection.BeginTransaction();
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = migration.Sql;
            command.ExecuteNonQuery();

            using var record = connection.CreateCommand();
            record.Transaction = transaction;
            record.CommandText = """
                INSERT INTO schema_migrations(version, name, applied_at)
                VALUES ($version, $name, $appliedAt);
                """;
            record.Parameters.AddWithValue("$version", migration.Version);
            record.Parameters.AddWithValue("$name", migration.Name);
            record.Parameters.AddWithValue(
                "$appliedAt",
                DateTimeOffset.UtcNow.ToString("O"));
            record.ExecuteNonQuery();
            transaction.Commit();
        }
    }

    private static void ConfigureDatabase(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            """;
        command.ExecuteNonQuery();
    }

    private static void EnsureMigrationTable(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            );
            """;
        command.ExecuteNonQuery();
    }

    private static HashSet<long> GetAppliedVersions(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT version FROM schema_migrations;";
        using var reader = command.ExecuteReader();
        var versions = new HashSet<long>();
        while (reader.Read())
        {
            versions.Add(reader.GetInt64(0));
        }

        return versions;
    }
}
