# Telemetry Engine

## Collection Boundary

Telemetry collects Windows observations only. It does not assign risk scores,
change trust policy, or perform response actions.

`WindowsTelemetryService` coordinates focused collectors:

- `ProcessTelemetryCollector`: process resource data and parent-child lineage.
- `StartupTelemetryCollector`: Run keys and startup folders.
- Windows PowerShell inventory: connections, scheduled tasks, services,
  Defender status, and firewall profiles.
- `AgentInstallationCollector`: running and uninstall-registry AI-agent
  inventory plus configured user-writable path observations.

Scheduled tasks and auto-start services are also projected into the existing
startup detection input. Their normalized records remain separate.

## Snapshot Model

One `TelemetrySnapshot` contains:

- Running processes, including parent process ID and name when available.
- TCP connections and UDP endpoints.
- Startup registry and folder entries.
- Scheduled tasks and action/trigger summaries.
- Windows services, state, start mode, executable, account, and PID.
- Microsoft Defender status and signature information.
- Windows Firewall profile state and default actions.
- Installed or running AI-agent observations.
- Executable/command references under configured user-writable paths.

Collection requests within `Telemetry:CollectionIntervalSeconds` reuse the same
snapshot. Concurrent requests coalesce behind one collection lock, preventing
the dashboard from launching duplicate inventory commands.

## Persistence

The telemetry repository commits all normalized domains and one audit record in
a single transaction. Persistence is independently throttled by
`Database:TelemetryPersistenceIntervalSeconds`.

Normalized tables:

- `telemetry_processes`
- `telemetry_network`
- `telemetry_startup`
- `telemetry_scheduled_tasks`
- `telemetry_services`
- `telemetry_defender`
- `telemetry_firewall`
- `telemetry_ai_agents`
- `telemetry_suspicious_paths`

All tables use `observed_at` for snapshot correlation and rolling retention.

## Read API

- `GET /api/telemetry/snapshot`
- `GET /api/process-tree`
- `GET /api/connections`
- `GET /api/processes`
- `GET /api/startup`
- `GET /api/scheduled-tasks`
- `GET /api/services`
- `GET /api/defender`
- `GET /api/firewall`
- `GET /api/installed-agents`
- `GET /api/suspicious-paths`

These routes are read-only. Privileged actions remain in the Response module.

## Limitations

- Protected process paths may be blank when Windows denies access.
- Parent PID data is best effort and can race with short-lived processes.
- AI-agent discovery currently covers running processes and Windows uninstall
  registry entries that match configured identity markers.
- Suspicious-path observations identify configured path locations; Detection
  decides whether the observation represents a threat.

