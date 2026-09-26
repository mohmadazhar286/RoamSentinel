namespace RoamSentinel.Database.Migrations;

public interface IDatabaseMigration
{
    long Version { get; }
    string Name { get; }
    string Sql { get; }
}

public interface IDatabaseMigrationRunner
{
    void Migrate();
}
