# RoamSentinel

RoamSentinel is a local-first Windows endpoint security and AI-agent governance
application. RS Console and the browser use one shared dashboard and the same
authenticated loopback API. RS Agent runs continuously as a Windows Service,
collects host telemetry, evaluates database-backed detection rules,
maps findings to MITRE ATT&CK, enriches indicators, and provides controlled
response actions through a localhost dashboard.

The product and assembly identity is RoamSentinel. Current development version:
`0.20.0-preview`.

## Capabilities

- Process, parent-child, network, startup, scheduled-task, service, Defender,
  Firewall, installed-agent, and suspicious-path telemetry
- Weighted detection rules with `info`, `low`, `medium`, `high`, and `critical`
  severity levels
- MITRE ATT&CK tactic and technique mapping
- Local IOCs and optional VirusTotal, AbuseIPDB, AlienVault OTX, and MISP
  enrichment
- AI-agent inventory, trust status, path controls, network activity, and risk
- Controlled process, Firewall, Defender, file, startup, and alert responses
- SQLite telemetry, findings, response evidence, settings, and audit records
- Administrator-only, checksummed ZIP backup export and integrity-validated
  restore through the API or CLI
- Windows Service hosting, ProgramData runtime storage, DPAPI local secret
  storage, and response-action dry-run mode
- Protection Scheduler module with shared-console health, due-state, and
  task-to-module ownership visibility
- RS Console with complete browser-console feature and route parity
- System-aware light/dark themes with an explicit theme selector
- Device Shield, RS CodeGate, and RS Insider module foundations
- Versioned Device Integrity inventory for drivers, installed software,
  registry persistence, monitored files, services, scheduled tasks, firewall
  profiles, network listeners, and PowerShell security posture
- Agent-owned Device Integrity baselines and explainable added/changed/removed
  events, collected independently of the console
- Device Integrity findings generated from baseline changes with review states
  for expected, suppressed, resolved, and open changes
- Offline RS CodeGate path scans for local files or repositories with
  redacted evidence, file hashes, persisted verdicts, and audit records
- Role-based local sessions, CSRF protection, validation, structured logs, and
  fail-closed write authorization

## Quick Start

Requirements:

- Windows 10 or later
- .NET 10 SDK
- PowerShell
- XAMPP is not required

```powershell
Set-Location C:\path\to\RoamSentinel
dotnet restore .\RoamSentinel.slnx
dotnet test .\RoamSentinel.slnx
.\scripts\Initialize-ResponseAuthorization.ps1
```

Restart PowerShell after creating the user-level token, run
`.\scripts\start.ps1`, then open `http://127.0.0.1:5117`.

Repeatable installation packages are produced with explicit profiles:

```powershell
.\scripts\Publish-RoamSentinel.ps1 -Profile Workstation
.\scripts\Publish-RoamSentinel.ps1 -Profile AgentOnly
.\scripts\Publish-RoamSentinel.ps1 -Profile CodeGateVm
```

Each publish output includes `install-profile.json` and is validated before
installation.

Offline CodeGate path scans can be run locally after migrations:

```powershell
& "$env:ProgramFiles\RoamSentinel\RoamSentinel.exe" `
  --codegate-scan C:\Repos\incoming `
  --source git-push `
  --revision main
```

For staging deployments, run the local deployment gate before promoting an app:

```powershell
& "$env:ProgramFiles\RoamSentinel\scripts\Invoke-RoamSentinelStagingGate.ps1" `
  -Path C:\Staging\incoming-app `
  -Revision release-candidate
```

Use `-FailOnWarn` when the staging environment should reject warnings as well
as blocked verdicts. See
[Personal protection and staging gate](docs/PERSONAL_PROTECTION_AND_STAGING_GATE.md).

For Git repositories hosted on a university VM, install the CodeGate hook
helper into a bare repository with `Install-CodeGateGitHook.ps1` and run it in
`pre-receive` or `post-receive` mode. The hook records actor, repository,
branch/ref, revision range, changed files, scan verdict, and audit evidence
without requiring internet access. Use `pre-receive` to block configured
blocking verdicts, or `post-receive` for audit-only recording. Each repository
gets a local `roamsentinel-codegate.policy.json` review point.

Before freezing VM network access, validate each repository hook policy:

```powershell
& "$env:ProgramFiles\RoamSentinel\scripts\Test-CodeGateGitHookPolicy.ps1" `
  -Repository D:\Git\example.git `
  -ExpectedMode pre-receive
```

For reviewed repository exceptions, record explicit local approval before
enforcing the policy:

```powershell
& "$env:ProgramFiles\RoamSentinel\scripts\Approve-CodeGateGitHookPolicy.ps1" `
  -Repository D:\Git\example.git `
  -ApprovedBy "security-admin" `
  -Reason "Reviewed VM pilot policy" `
  -Ticket "RS-VM-001"
```

Periodic offline evidence exports can be written locally with retention:

```powershell
& "$env:ProgramFiles\RoamSentinel\scripts\Invoke-RoamSentinelEvidenceExport.ps1" `
  -OutputDirectory D:\RoamSentinelEvidence `
  -RetentionDays 30 `
  -Repository D:\Git\example.git `
  -RequireApproval
```

Each evidence export includes a backup ZIP, `scheduler-status.json`, and any
requested CodeGate hook policy review output.

Scheduler health can also be exported directly:

```powershell
& "$env:ProgramFiles\RoamSentinel\RoamSentinel.exe" `
  --scheduler-status `
  --json `
  --output D:\RoamSentinelEvidence\scheduler-status.json
```

Offline CodeGate rule/advisory/IOC bundles can be imported after copying them
to the VM:

```powershell
& "$env:ProgramFiles\RoamSentinel\RoamSentinel.exe" `
  --import-codegate-bundle C:\Bundles\codegate-rules.json `
  --sha256 <expected-sha256>
```

The importer records freshness metadata and locally computed SHA-256. It does
not activate arbitrary imported rules yet.

Analyst-authenticated CodeGate CSV exports are available from the shared
console for submissions, Git push audits, and offline bundle freshness. The
exports use the same loopback API as browser mode and are intended for local VM
review after internet access is disabled. Submission and Git push rows also
provide Analyst-only drilldown for redacted findings, changed files, revisions,
actors, and content hashes.

MobileBridge pairing is available for local companion/test enrollment. Unlock
RS Console as Administrator, create a 10-minute pairing code, then scan the
offline QR payload or run the generated command with the installed helper:

```text
rs://pair?c=123456&b=http%3A%2F%2F127.0.0.1%3A5117
```

```powershell
& "$env:ProgramFiles\RoamSentinel\scripts\Register-RoamSentinelMobileDevice.ps1" `
  -PairingCode 123456 `
  -DeviceId android-test-1 `
  -DisplayName "My Android Phone" `
  -Platform Android
```

The helper also accepts the full scanned URI:

```powershell
& "$env:ProgramFiles\RoamSentinel\scripts\Register-RoamSentinelMobileDevice.ps1" `
  -PairingPayload "rs://pair?c=123456&b=http%3A%2F%2F127.0.0.1%3A5117" `
  -DeviceId android-test-1
```

The enrollment response returns a device token. Store it securely; the token is
required for later heartbeat, inventory, and finding submissions. The QR
contains only the temporary pairing code and loopback base URL; it does not
contain the device token. The current MobileBridge surface remains bound to
loopback and does not include a packaged phone companion app.

RoamSentinel is hosted by ASP.NET Core Kestrel. Apache and MySQL are not
required and should not be configured to expose this dashboard.

## Documentation

- [Installation](INSTALL.md)
- [Architecture](ARCHITECTURE.md)
- [RSAS v1.0 architecture specification](docs/RSAS-v1.0.md)
- [Module experience architecture](docs/MODULE_EXPERIENCE_ARCHITECTURE.md)
- [Broadened product scope](docs/BROADENED_SCOPE.md)
- [Personal protection and staging gate](docs/PERSONAL_PROTECTION_AND_STAGING_GATE.md)
- [Offline university VM deployment](docs/OFFLINE_VM_DEPLOYMENT.md)
- [Offline VM release checklist](docs/OFFLINE_VM_RELEASE_CHECKLIST.md)
- [Security model](SECURITY_MODEL.md)
- [Administrator guide](ADMIN_GUIDE.md)
- [Testing](TESTING.md)
- [Roadmap](ROADMAP.md)
- [Changelog](CHANGELOG.md)
- [License placeholder](LICENSE)
- [Installer readiness](docs/INSTALLER_READINESS.md)
- [Commercial readiness review](docs/COMMERCIAL_READINESS_REVIEW.md)

Detailed implementation notes remain under [`docs`](docs).

## Project Layout

| Path | Responsibility |
|---|---|
| `app` | Composition root, API commands, queries, and HTTP security |
| `Core` | Contracts and immutable domain models |
| `Telemetry` | Read-only Windows collection |
| `Detection` | Rules, risk scoring, and findings |
| `Response` | Privileged endpoint actions |
| `ThreatIntel` | IOC normalization and provider adapters |
| `AgentGovernance` | Agent identity, trust, and risk |
| `DeviceShield` | RS Agent protection capability registration |
| `CodeGate` | RS CodeGate scan/verdict contracts and registration |
| `InsiderRisk` | RS Insider risk capability registration |
| `Console` | RS Console host for the shared dashboard |
| `Dashboard` | Read-only dashboard section endpoints |
| `Database` | SQLite repositories and migrations |
| `Config` | Validated platform configuration |
| `Logs` | Structured application and security logs |
| `public` | Shared Browser Console and RS Console dashboard assets |
| `tests` | Automated xUnit tests |

## Product Components

- **RS Agent** runs endpoint protection.
- **RS Console** shows the complete local dashboard.
- **RS CodeGate** scans imported or pushed code.
- **RS Control** is the future organization management plane.
- **RS Insider** provides the user-risk engine.

## Operational Notes

- The bind URL is validated as loopback-only.
- Read-only monitoring can run without elevation; several response actions
  require an elevated process.
- Defender full scans run asynchronously and may continue for hours.
- Security events persist until an administrator purges reviewed events.
- Structured log files use configured age-based retention.
- Telemetry uses rolling database retention, seven days by default.
- Back up `data\roamsentinel.db` while the app is stopped.

RoamSentinel supplements Microsoft Defender and Windows Firewall. It is not a
replacement for patching, backups, disk encryption, or enterprise EDR.
