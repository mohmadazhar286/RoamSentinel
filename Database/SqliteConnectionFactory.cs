using Microsoft.Data.Sqlite;
using RoamSentinel.Config;
using RoamSentinel.Core;

namespace RoamSentinel.Database;

public sealed class SqliteConnectionFactory : IDatabaseConnectionFactory
{
    private readonly string _connectionString;
    private readonly DatabaseOptions _options;

    public SqliteConnectionFactory(
        IRuntimePathService runtimePaths,
        DatabaseOptions options)
        : this(runtimePaths.ResolveDataPath(options.FilePath), options, true)
    {
    }

    public SqliteConnectionFactory(
        string contentRootPath,
        DatabaseOptions options)
        : this(Path.GetFullPath(
            Path.IsPathRooted(options.FilePath)
                ? options.FilePath
                : Path.Combine(contentRootPath, options.FilePath)), options, true)
    {
    }

    private SqliteConnectionFactory(
        string resolvedPath,
        DatabaseOptions options,
        bool _)
    {
        _options = options;
        DatabasePath = resolvedPath;

        var directory = Path.GetDirectoryName(DatabasePath)
            ?? throw new InvalidOperationException(
                "Database path must include a parent directory.");
        Directory.CreateDirectory(directory);

        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = DatabasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            ForeignKeys = true,
            DefaultTimeout = options.CommandTimeoutSeconds,
            Pooling = true
        }.ToString();
    }

    public string DatabasePath { get; }

    public SqliteConnection OpenConnection()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = $"PRAGMA busy_timeout={_options.BusyTimeoutMilliseconds};";
        command.ExecuteNonQuery();
        return connection;
    }
}
