namespace RoamSentinel.Database.Migrations;

public sealed class DeviceIntegrityMigration : IDatabaseMigration
{
    public long Version => 2026070701;
    public string Name => "device_integrity_baselines_and_events";
    public string Sql => """
        CREATE TABLE device_integrity_inventory (
            entity_type TEXT NOT NULL,
            entity_key TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            PRIMARY KEY (entity_type, entity_key)
        );
        CREATE TABLE device_integrity_events (
            event_id TEXT PRIMARY KEY,
            observed_at TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_key TEXT NOT NULL,
            change_type TEXT NOT NULL CHECK (
                change_type IN ('added', 'changed', 'removed')),
            before_json TEXT NOT NULL,
            after_json TEXT NOT NULL,
            explanation TEXT NOT NULL
        );
        CREATE INDEX ix_device_integrity_events_observed
            ON device_integrity_events(observed_at DESC);
        """;
}
