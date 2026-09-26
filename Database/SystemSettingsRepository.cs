using System.Text.Json;
using RoamSentinel.Core;

namespace RoamSentinel.Database;

public sealed class SystemSettingsRepository(
    IDatabaseConnectionFactory connections,
    IStructuredLogService logs) : ISystemSettingsRepository
{
    private static readonly IReadOnlyDictionary<string, (int Min, int Max)>
        IntegerSettings = new Dictionary<string, (int, int)>(
            StringComparer.OrdinalIgnoreCase)
        {
            ["dashboard.refresh_interval_ms"] = (1000, 60000),
            ["logs.retention_days"] = (1, 365),
            ["telemetry.retention_days"] = (1, 365)
        };

    public IReadOnlyList<SystemSettingDto> GetAll()
    {
        using var connection = connections.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT setting_key, setting_value, value_type, updated_at
            FROM system_settings
            ORDER BY setting_key;
            """;
        using var reader = command.ExecuteReader();
        var settings = new List<SystemSettingDto>();
        while (reader.Read())
        {
            settings.Add(new SystemSettingDto(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                DateTimeOffset.Parse(reader.GetString(3))));
        }

        return settings;
    }

    public SystemSettingDto Set(string key, string value, string actor)
    {
        if (!IntegerSettings.TryGetValue(key, out var range) ||
            !int.TryParse(value, out var number) ||
            number < range.Min ||
            number > range.Max)
        {
            throw new ArgumentException(
                "Unsupported setting or value outside the permitted range.");
        }

        var now = DateTimeOffset.UtcNow;
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO system_settings (
                setting_key, setting_value, value_type, updated_at
            ) VALUES (
                $key, $value, 'integer', $updatedAt
            )
            ON CONFLICT(setting_key) DO UPDATE SET
                setting_value = excluded.setting_value,
                value_type = excluded.value_type,
                updated_at = excluded.updated_at;
            """;
        command.Parameters.AddWithValue("$key", key);
        command.Parameters.AddWithValue("$value", number.ToString());
        command.Parameters.AddWithValue("$updatedAt", now.ToString("O"));
        command.ExecuteNonQuery();
        AuditSql.Insert(
            connection,
            transaction,
            actor,
            "settings.changed",
            "system_setting",
            key,
            true,
            JsonSerializer.Serialize(new { Value = number }));
        transaction.Commit();
        logs.Security(
            "settings.changed",
            "System setting changed.",
            new { Key = key, Value = number, Actor = actor });
        return new SystemSettingDto(
            key,
            number.ToString(),
            "integer",
            now);
    }
}
