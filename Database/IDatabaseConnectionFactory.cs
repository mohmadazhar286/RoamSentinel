using Microsoft.Data.Sqlite;

namespace RoamSentinel.Database;

public interface IDatabaseConnectionFactory
{
    string DatabasePath { get; }
    SqliteConnection OpenConnection();
}
