using System.Text.Json;
using RoamSentinel.Core;

namespace RoamSentinel.Database;

public sealed class IpBlockRepository(
    IDatabaseConnectionFactory connections) : IIpBlockRepository
{
    public IReadOnlyList<IpBlockDto> Load()
    {
        using var connection = connections.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT ip_address, display_name, blocked_at
            FROM ip_blocks
            ORDER BY blocked_at DESC;
            """;

        using var reader = command.ExecuteReader();
        var blocks = new List<IpBlockDto>();
        while (reader.Read())
        {
            blocks.Add(new IpBlockDto(
                reader.GetString(0),
                reader.GetString(1),
                DateTimeOffset.Parse(reader.GetString(2))));
        }

        return blocks;
    }

    public IpBlockDto? Find(string ipAddress)
    {
        using var connection = connections.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT ip_address, display_name, blocked_at
            FROM ip_blocks
            WHERE ip_address = $ipAddress;
            """;
        command.Parameters.AddWithValue("$ipAddress", ipAddress);
        using var reader = command.ExecuteReader();
        return reader.Read()
            ? new IpBlockDto(
                reader.GetString(0),
                reader.GetString(1),
                DateTimeOffset.Parse(reader.GetString(2)))
            : null;
    }

    public void Upsert(IpBlockDto block)
    {
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO ip_blocks(ip_address, display_name, blocked_at)
            VALUES ($ipAddress, $displayName, $blockedAt)
            ON CONFLICT(ip_address) DO UPDATE SET
                display_name = excluded.display_name,
                blocked_at = excluded.blocked_at;
            """;
        command.Parameters.AddWithValue("$ipAddress", block.IpAddress);
        command.Parameters.AddWithValue("$displayName", block.DisplayName);
        command.Parameters.AddWithValue(
            "$blockedAt",
            block.BlockedAt.ToUniversalTime().ToString("O"));
        command.ExecuteNonQuery();
        AuditSql.Insert(
            connection,
            transaction,
            "system",
            "ip_block.upserted",
            "ip_block",
            block.IpAddress,
            true,
            JsonSerializer.Serialize(new { block.DisplayName }));
        transaction.Commit();
    }

    public void Remove(string ipAddress)
    {
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            "DELETE FROM ip_blocks WHERE ip_address = $ipAddress;";
        command.Parameters.AddWithValue("$ipAddress", ipAddress);
        var deleted = command.ExecuteNonQuery();
        AuditSql.Insert(
            connection,
            transaction,
            "system",
            "ip_block.removed",
            "ip_block",
            ipAddress,
            deleted > 0,
            JsonSerializer.Serialize(new { Deleted = deleted }));
        transaction.Commit();
    }
}
