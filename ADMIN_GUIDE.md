# Administrator Guide

## Start and Sign In

From the RoamSentinel repository root:

```powershell
.\scripts\start.ps1
```

Open `http://127.0.0.1:5117` and sign in with the token assigned to your role.
Run the shell as Administrator only when privileged response controls are
needed.

## Role Allocation

- Give `Viewer` tokens to users who only review posture and telemetry.
- Give `Analyst` tokens to users who enrich indicators and disposition alerts.
- Restrict `Administrator` tokens to operators allowed to alter policy or the
  endpoint.
- Use separate random tokens for each role.
- Rotate a token by replacing its user environment variable and restarting the
  application. Existing in-memory sessions are also removed by restart.

## Routine Review

Daily:

1. Review Security Overview and critical/high alerts.
2. Confirm Defender and Firewall are enabled.
3. Inspect unknown or blocked agents that are running.
4. Review unexpected public network destinations.
5. Check Response History for failed or denied actions.

Weekly:

1. Review Alerts, MITRE ATT&CK View, Audit Log, and structured logs.
2. Investigate new startup items, services, and scheduled tasks.
3. Review trusted and blocked agent paths.
4. Back up the SQLite database.
5. Purge reviewed security events only after evidence is no longer required.

## Response Actions

| Action | Operational effect |
|---|---|
| Quick/full/deep scan | Launches Microsoft Defender asynchronously |
| Kill process | Stops a non-protected process by PID |
| Block/unblock IP | Manages paired RoamSentinel Firewall rules |
| Quarantine file | Requests Defender scan/remediation for an allowed path |
| Disable startup | Disables a supported persistence entry and stores recovery metadata |
| Resolve/false positive | Preserves the alert with review disposition |
| Trust/block/unblock agent | Updates policy and associated outbound Firewall rules |

Review the target and before-state before acting. A successful command means
the requested operation completed; it does not prove the endpoint is clean.

Full Defender scans can take a long time. RoamSentinel reports launch status
without waiting for scan completion.

## AI-Agent Policy

- Trust only the exact executable path you reviewed.
- Treat copies under downloads, temporary folders, and user-writable tool
  directories as separate observations.
- Do not enforce a whole-program block against shared hosts unless the dashboard
  explicitly marks the path enforceable.
- Re-review an agent after upgrades because its path, publisher, or host process
  may change.

## Detection Rules and Settings

Administrators can enable or disable database-backed rules. Disabled rules stop
new findings but do not delete historical evidence.

Dashboard-editable settings are whitelisted, validated, parameterized, and
audited. Configuration that affects credentials, bind address, provider URLs,
or database paths remains deployment configuration and requires restart.

## Logs and Retention

Structured files:

- `Logs\app.log`
- `Logs\security.log`
- `Logs\response.log`
- `Logs\error.log`

Security events and audit entries are separate database records. Purging
reviewed security events does not silently erase response history or the audit
trail. Structured file retention defaults to seven days; telemetry database
retention also defaults to seven days.

## Backup and Restore

Administrators can open **Settings** and select **Export backup**. The download
is a ZIP containing:

- a transactionally consistent `roamsentinel.db`
- `manifest.json` with product, version, time, host, and migration metadata
- `RESTORE.txt`

Access tokens and threat-intelligence API keys are intentionally excluded.
Every export is written to the audit log.

Command-line fallback:

```powershell
.\scripts\stop.ps1
Copy-Item .\data\roamsentinel.db D:\Backups\roamsentinel.db
.\scripts\start.ps1
```

To restore, stop RoamSentinel, preserve the current database separately, copy
the selected backup to `data\roamsentinel.db`, then start the app. Validate the
Database Status and Audit Log views after restore.

When copying a live WAL database, copy the `.db`, `.db-wal`, and `.db-shm`
files together. A stopped backup is simpler and safer.

## Troubleshooting

**Port 5117 already in use**

```powershell
Get-NetTCPConnection -LocalPort 5117 -State Listen |
  Select-Object OwningProcess
.\scripts\stop.ps1
```

**Access denied for protected Windows paths**

Some task folders and process details are intentionally inaccessible without
additional rights. Collection skips inaccessible task directories. Run
elevated only when the additional visibility is justified.

**Response action says elevation is required**

Stop the app and restart PowerShell with **Run as administrator**.

**Login fails**

Confirm the correct environment variable exists in the same user context, open
a new shell after changing user variables, and restart RoamSentinel. Tokens
must be 16 to 512 characters.

**Threat-intelligence provider is unavailable**

Check provider enablement, API key, base URL, quota, TLS, and `Logs\error.log`.
Other configured providers continue independently.

**Database is locked**

Ensure only one RoamSentinel process uses the database. Stop duplicate
instances and avoid copying only one file from a live WAL database.

## Safe Update Procedure

1. Stop RoamSentinel.
2. Back up the database and deployment configuration.
3. Update source files.
4. Run `dotnet test .\RoamSentinel.slnx`.
5. Start the application.
6. Check Database Status, Security Overview, Response History, and Error Log.

See [INSTALL.md](INSTALL.md), [SECURITY_MODEL.md](SECURITY_MODEL.md), and
[TESTING.md](TESTING.md) for deployment and verification detail.
