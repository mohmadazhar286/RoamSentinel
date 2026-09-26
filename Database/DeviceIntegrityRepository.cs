using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using RoamSentinel.Core;

namespace RoamSentinel.Database;

public sealed class DeviceIntegrityRepository(
    IDatabaseConnectionFactory connections) : IDeviceIntegrityRepository
{
    public IReadOnlyList<DeviceIntegrityChangeEvent> RecordSnapshot(
        DeviceIntegritySnapshot snapshot)
    {
        var observed = Flatten(snapshot);
        using var connection = connections.OpenConnection();
        using var transaction = connection.BeginTransaction();
        var existing = ReadCurrent(connection, transaction);
        var changes = new List<DeviceIntegrityChangeEvent>();
        var hasBaseline = existing.Count > 0;

        foreach (var item in observed)
        {
            var identity = (item.Type, item.Key);
            existing.TryGetValue(identity, out var before);
            if (hasBaseline && before is null)
            {
                changes.Add(CreateChange(
                    snapshot.ObservedAt, item, "added", "{}", item.Json));
            }
            else if (before is not null &&
                     before.Fingerprint != item.Fingerprint)
            {
                changes.Add(CreateChange(
                    snapshot.ObservedAt,
                    item,
                    "changed",
                    before.Json,
                    item.Json));
            }

            Upsert(connection, transaction, item, snapshot.ObservedAt);
            existing.Remove(identity);
        }

        if (hasBaseline)
        {
            foreach (var removed in existing)
            {
                var item = new InventoryItem(
                    removed.Key.Type,
                    removed.Key.Key,
                    removed.Value.Fingerprint,
                    removed.Value.Json);
                changes.Add(CreateChange(
                    snapshot.ObservedAt,
                    item,
                    "removed",
                    item.Json,
                    "{}"));
                Delete(connection, transaction, item);
            }
        }

        foreach (var change in changes)
        {
            InsertEvent(connection, transaction, change);
        }

        AuditSql.Insert(
            connection,
            transaction,
            "system",
            "device_integrity.snapshot.recorded",
            "device_integrity",
            snapshot.ObservedAt.ToString("O"),
            true,
            JsonSerializer.Serialize(new
            {
                Entities = observed.Count,
                Changes = changes.Count,
                BaselineCreated = !hasBaseline
            }));
        transaction.Commit();
        return changes;
    }

    public IReadOnlyList<DeviceIntegrityChangeEvent> GetRecentEvents(int limit)
    {
        using var connection = connections.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT event_id, observed_at, entity_type, entity_key,
                   change_type, before_json, after_json, explanation
            FROM device_integrity_events
            ORDER BY observed_at DESC
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 1000));
        using var reader = command.ExecuteReader();
        var result = new List<DeviceIntegrityChangeEvent>();
        while (reader.Read())
        {
            result.Add(new(
                reader.GetString(0),
                DateTimeOffset.Parse(reader.GetString(1)),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetString(4),
                reader.GetString(5),
                reader.GetString(6),
                reader.GetString(7)));
        }

        return result;
    }

    private static List<InventoryItem> Flatten(DeviceIntegritySnapshot snapshot)
    {
        var items = snapshot.Drivers.Select(item =>
                Create("driver", item.Name, item))
            .Concat(snapshot.InstalledSoftware.Select(item =>
                Create("software", $"{item.Name}|{item.Publisher}", item)))
            .Concat(snapshot.RegistryPersistence.Select(item =>
                Create(
                    "registry-persistence",
                    $"{item.Hive}|{item.Key}|{item.Name}",
                    item)))
            .Concat(snapshot.MonitoredFiles.Select(item =>
                Create("file", item.Path, item)))
            .Concat(snapshot.Services.Select(item =>
                Create("service", item.Name, item)))
            .Concat(snapshot.ScheduledTasks.Select(item =>
                Create("scheduled-task", $"{item.Path}|{item.Name}", item)))
            .Concat(snapshot.FirewallProfiles.Select(item =>
                Create("firewall-profile", item.Name, item)))
            .Concat(snapshot.NetworkListeners.Select(item =>
                Create(
                    "network-listener",
                    $"{item.Protocol}|{item.LocalAddress}|{item.LocalPort}|{item.ProcessId}",
                    item)))
            .Append(Create(
                "powershell",
                "local-machine",
                snapshot.PowerShell));
        return items
            .GroupBy(item => (item.Type, item.Key))
            .Select(group => group.First())
            .ToList();
    }

    private static InventoryItem Create(string type, string key, object value)
    {
        var json = JsonSerializer.Serialize(value);
        var fingerprint = Convert.ToHexString(SHA256.HashData(
            Encoding.UTF8.GetBytes(json)));
        return new(type, key, fingerprint, json);
    }

    private static Dictionary<(string Type, string Key), StoredItem> ReadCurrent(
        SqliteConnection connection,
        SqliteTransaction transaction)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT entity_type, entity_key, fingerprint, payload_json
            FROM device_integrity_inventory;
            """;
        using var reader = command.ExecuteReader();
        var result = new Dictionary<(string, string), StoredItem>();
        while (reader.Read())
        {
            result[(reader.GetString(0), reader.GetString(1))] =
                new(reader.GetString(2), reader.GetString(3));
        }
        return result;
    }

    private static void Upsert(
        SqliteConnection connection,
        SqliteTransaction transaction,
        InventoryItem item,
        DateTimeOffset observedAt)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO device_integrity_inventory(
                entity_type, entity_key, fingerprint, payload_json,
                first_seen_at, last_seen_at)
            VALUES($type,$key,$fingerprint,$json,$time,$time)
            ON CONFLICT(entity_type,entity_key) DO UPDATE SET
                fingerprint=excluded.fingerprint,
                payload_json=excluded.payload_json,
                last_seen_at=excluded.last_seen_at;
            """;
        command.Parameters.AddWithValue("$type", item.Type);
        command.Parameters.AddWithValue("$key", item.Key);
        command.Parameters.AddWithValue("$fingerprint", item.Fingerprint);
        command.Parameters.AddWithValue("$json", item.Json);
        command.Parameters.AddWithValue("$time", observedAt.ToString("O"));
        command.ExecuteNonQuery();
    }

    private static void Delete(
        SqliteConnection connection,
        SqliteTransaction transaction,
        InventoryItem item)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            DELETE FROM device_integrity_inventory
            WHERE entity_type=$type AND entity_key=$key;
            """;
        command.Parameters.AddWithValue("$type", item.Type);
        command.Parameters.AddWithValue("$key", item.Key);
        command.ExecuteNonQuery();
    }

    private static DeviceIntegrityChangeEvent CreateChange(
        DateTimeOffset observedAt,
        InventoryItem item,
        string change,
        string before,
        string after) =>
        new(
            Guid.NewGuid().ToString(),
            observedAt,
            item.Type,
            item.Key,
            change,
            before,
            after,
            $"{item.Type} '{item.Key}' was {change}.");

    private static void InsertEvent(
        SqliteConnection connection,
        SqliteTransaction transaction,
        DeviceIntegrityChangeEvent item)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO device_integrity_events(
                event_id,observed_at,entity_type,entity_key,change_type,
                before_json,after_json,explanation)
            VALUES($id,$time,$type,$key,$change,$before,$after,$explanation);
            """;
        command.Parameters.AddWithValue("$id", item.EventId);
        command.Parameters.AddWithValue("$time", item.ObservedAt.ToString("O"));
        command.Parameters.AddWithValue("$type", item.EntityType);
        command.Parameters.AddWithValue("$key", item.EntityKey);
        command.Parameters.AddWithValue("$change", item.ChangeType);
        command.Parameters.AddWithValue("$before", item.BeforeJson);
        command.Parameters.AddWithValue("$after", item.AfterJson);
        command.Parameters.AddWithValue("$explanation", item.Explanation);
        command.ExecuteNonQuery();
    }

    private sealed record InventoryItem(
        string Type,
        string Key,
        string Fingerprint,
        string Json);
    private sealed record StoredItem(string Fingerprint, string Json);
}
