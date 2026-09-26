# Database and Configuration

## Storage

RoamSentinel uses SQLite through a single `IDatabaseConnectionFactory`.
The default database is `data/roamsentinel.db`; relative paths are resolved
against the application content root.

SQLite runs with foreign keys enabled, WAL journaling, a configurable busy
timeout, and pooled connections. The database, WAL, and shared-memory files
must be backed up together while the application is running. Stopping the
application before copying `roamsentinel.db` is the simpler backup method.

## Schema Migrations

`DatabaseMigrationRunner` runs before HTTP requests are accepted. Each
`IDatabaseMigration` has a monotonically increasing version and executes once
inside a transaction. Applied versions are recorded in `schema_migrations`.

To add a schema change:

1. Add an `IDatabaseMigration` implementation under `Database/Migrations`.
2. Give it a version greater than the latest committed version.
3. Register it in `app/Program.cs`.
4. Add migration and repository tests.

Do not edit an already released migration. Add a new migration instead.

## Tables

The initial migration creates:

- `security_events`
- `telemetry_processes`
- `telemetry_network`
- `telemetry_startup`
- `telemetry_scheduled_tasks`
- `telemetry_services`
- `telemetry_defender`
- `telemetry_firewall`
- `telemetry_ai_agents`
- `telemetry_suspicious_paths`
- `detection_rules`
- `threat_indicators`
- `mitre_mappings`
- `mitre_techniques`
- `detection_findings`
- `response_actions`
- `agent_registry`
- `agent_activity`
- `audit_log`
- `system_settings`
- `ip_blocks`

`schema_migrations` is maintained by the migration runner.

## Audit Contract

Repository mutations write their domain change and an `audit_log` row in the
same SQLite transaction. This covers event changes and purge operations,
agent-policy changes, IP blocks, response attempts, and telemetry snapshots.
Local IOC changes and provider-cache updates are audited as database mutations.
Failed response attempts are recorded with `success = 0`.

Migration bookkeeping is recorded in `schema_migrations`; audit records are not
recursively audited.

## Legacy Import

On first start, the importer reads the former JSON stores when present:

- `data/events.jsonl`
- `data/agent-policy.json`
- `data/ip-blocks.json`

Completion is recorded in `system_settings` as
`legacy_json_import.completed`. The source files are not deleted. Set
`Database:ImportLegacyJson` to `false` to disable import.

## Configuration

Safe local defaults live in `appsettings.json`. ASP.NET Core environment
variables can override them using double underscores:

```powershell
$env:Database__FilePath = 'D:\RoamSentinel\roamsentinel.db'
$env:Database__TelemetryRetentionDays = '14'
$env:Dashboard__RefreshIntervalMilliseconds = '10000'
dotnet run --project C:\path\to\RoamSentinel
```

The bind URL must remain loopback-only. Do not store credentials or API keys in
`appsettings.json`; provide secrets through the process environment or a
deployment-specific configuration provider.

Important retention settings:

- `Telemetry:CollectionIntervalSeconds`: in-memory snapshot collection interval
  and concurrent-request coalescing window.
- `Database:TelemetryPersistenceIntervalSeconds`: minimum interval between
  persisted snapshots.
- `Database:TelemetryRetentionDays`: rolling telemetry history.
- Security events and audit records remain until an explicit operator purge.
- Periodic evidence export retention is handled by
  `scripts\Invoke-RoamSentinelEvidenceExport.ps1`, which deletes old
  `RoamSentinel-evidence-*` export directories according to the operator's
  `RetentionDays` value.
