using System.Text.Json;
using RoamSentinel.Core;

namespace RoamSentinel.Database;

public sealed class ThreatIndicatorRepository(
    IDatabaseConnectionFactory connections) : IThreatIndicatorRepository
{
    public IReadOnlySet<string> GetActiveSuspiciousIps(DateTimeOffset asOf)
    {
        using var connection = connections.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT DISTINCT indicator
            FROM threat_indicators
            WHERE lower(indicator_type) = 'ip'
              AND lower(reputation) IN (
                  'suspicious', 'malicious', 'high-risk', 'blocked'
              )
              AND (expires_at IS NULL OR expires_at > $asOf);
            """;
        command.Parameters.AddWithValue("$asOf", ToSql(asOf));
        using var reader = command.ExecuteReader();
        var indicators = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        while (reader.Read())
        {
            indicators.Add(reader.GetString(0));
        }

        return indicators;
    }

    public IReadOnlyList<ThreatIndicatorDto> GetAll(int limit)
    {
        using var connection = connections.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT indicator, indicator_type, reputation, confidence, source,
                   first_seen_at, last_seen_at, expires_at, description,
                   tags_json, metadata_json
            FROM threat_indicators
            ORDER BY last_seen_at DESC
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 5000));
        using var reader = command.ExecuteReader();
        var indicators = new List<ThreatIndicatorDto>();
        while (reader.Read())
        {
            indicators.Add(Read(reader));
        }

        return indicators;
    }

    public ThreatIndicatorDto? FindActive(
        string indicator,
        string indicatorType,
        string source,
        DateTimeOffset asOf)
    {
        using var connection = connections.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT indicator, indicator_type, reputation, confidence, source,
                   first_seen_at, last_seen_at, expires_at, description,
                   tags_json, metadata_json
            FROM threat_indicators
            WHERE indicator = $indicator
              AND lower(indicator_type) = lower($indicatorType)
              AND lower(source) = lower($source)
              AND (expires_at IS NULL OR expires_at > $asOf)
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("$indicator", indicator);
        command.Parameters.AddWithValue("$indicatorType", indicatorType);
        command.Parameters.AddWithValue("$source", source);
        command.Parameters.AddWithValue("$asOf", ToSql(asOf));
        using var reader = command.ExecuteReader();
        return reader.Read() ? Read(reader) : null;
    }

    public ThreatIndicatorDto Upsert(
        ThreatIndicatorDto indicator,
        string actor)
    {
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO threat_indicators (
                indicator, indicator_type, reputation, confidence, source,
                first_seen_at, last_seen_at, expires_at, metadata_json,
                description, tags_json, updated_at
            ) VALUES (
                $indicator, $indicatorType, $reputation, $confidence, $source,
                $firstSeenAt, $lastSeenAt, $expiresAt, $metadataJson,
                $description, $tagsJson, $updatedAt
            )
            ON CONFLICT(indicator, source) DO UPDATE SET
                indicator_type = excluded.indicator_type,
                reputation = excluded.reputation,
                confidence = excluded.confidence,
                last_seen_at = excluded.last_seen_at,
                expires_at = excluded.expires_at,
                metadata_json = excluded.metadata_json,
                description = excluded.description,
                tags_json = excluded.tags_json,
                updated_at = excluded.updated_at;
            """;
        command.Parameters.AddWithValue("$indicator", indicator.Indicator);
        command.Parameters.AddWithValue(
            "$indicatorType",
            indicator.IndicatorType);
        command.Parameters.AddWithValue("$reputation", indicator.Reputation);
        command.Parameters.AddWithValue("$confidence", indicator.Confidence);
        command.Parameters.AddWithValue("$source", indicator.Source);
        command.Parameters.AddWithValue(
            "$firstSeenAt",
            ToSql(indicator.FirstSeenAt));
        command.Parameters.AddWithValue(
            "$lastSeenAt",
            ToSql(indicator.LastSeenAt));
        command.Parameters.AddWithValue(
            "$expiresAt",
            indicator.ExpiresAt is null
                ? DBNull.Value
                : ToSql(indicator.ExpiresAt.Value));
        command.Parameters.AddWithValue("$metadataJson", indicator.MetadataJson);
        command.Parameters.AddWithValue("$description", indicator.Description);
        command.Parameters.AddWithValue(
            "$tagsJson",
            JsonSerializer.Serialize(indicator.Tags));
        command.Parameters.AddWithValue(
            "$updatedAt",
            ToSql(DateTimeOffset.UtcNow));
        command.ExecuteNonQuery();
        AuditSql.Insert(
            connection,
            transaction,
            actor,
            "threat_indicator.upserted",
            "threat_indicator",
            $"{indicator.IndicatorType}:{indicator.Indicator}:{indicator.Source}",
            true,
            JsonSerializer.Serialize(new
            {
                indicator.Reputation,
                indicator.Confidence,
                indicator.ExpiresAt
            }));
        transaction.Commit();
        return indicator;
    }

    public bool RemoveLocal(string indicator, string indicatorType)
    {
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            DELETE FROM threat_indicators
            WHERE indicator = $indicator
              AND lower(indicator_type) = lower($indicatorType)
              AND source = 'Local';
            """;
        command.Parameters.AddWithValue("$indicator", indicator);
        command.Parameters.AddWithValue("$indicatorType", indicatorType);
        var deleted = command.ExecuteNonQuery();
        AuditSql.Insert(
            connection,
            transaction,
            "local-user",
            "threat_indicator.local_removed",
            "threat_indicator",
            $"{indicatorType}:{indicator}:Local",
            deleted > 0,
            JsonSerializer.Serialize(new { Deleted = deleted }));
        transaction.Commit();
        return deleted > 0;
    }

    private static ThreatIndicatorDto Read(
        Microsoft.Data.Sqlite.SqliteDataReader reader) =>
        new(
            reader.GetString(0),
            reader.GetString(1),
            reader.GetString(2),
            reader.GetInt32(3),
            reader.GetString(4),
            DateTimeOffset.Parse(reader.GetString(5)),
            DateTimeOffset.Parse(reader.GetString(6)),
            reader.IsDBNull(7)
                ? null
                : DateTimeOffset.Parse(reader.GetString(7)),
            reader.GetString(8),
            ReadTags(reader.GetString(9)),
            reader.GetString(10));

    private static IReadOnlyList<string> ReadTags(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<string[]>(json) ?? [];
        }
        catch
        {
            return [];
        }
    }

    private static string ToSql(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("O");
}
