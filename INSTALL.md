# Installation

## Supported Environment

- Windows 10 or Windows 11
- .NET 10 SDK, matching the `net10.0-windows` target
- PowerShell 5.1 or later
- Microsoft Defender and Windows Firewall for native response integrations
- Administrator rights when using privileged response actions

XAMPP is not a runtime dependency. RoamSentinel does not use Apache, PHP, or
MySQL. ASP.NET Core Kestrel serves the application directly on loopback.

## XAMPP Workspace Setup

If XAMPP is already installed, place or clone the repository at:

```text
C:\path\to\RoamSentinel
```

If XAMPP is not installed, either install it to `C:\xampp` and use that path,
or place the repository in another writable directory. Development and
installed binaries remain in the application directory. Mutable runtime state
is stored under `%ProgramData%\RoamSentinel`:

- `data\roamsentinel.db`
- `logs\`
- `config\appsettings.json` and DPAPI-protected local secrets

Apache may remain stopped. If it is running for other projects, it can continue
using ports 80/443 while RoamSentinel uses `127.0.0.1:5117`. Do not publish or
reverse-proxy RoamSentinel through Apache.

## Production Service Installation

Run an elevated PowerShell:

```powershell
.\scripts\Publish-RoamSentinel.ps1 -Profile Workstation
.\scripts\Install-RoamSentinelService.ps1 `
  -PublishDirectory .\artifacts\publish\win-x64 `
  -Profile Workstation
```

The service is named `RoamSentinel`, starts automatically, and retains
ProgramData during uninstall. The default profile installs the native
`RoamSentinel Management Console` and creates Start Menu and Public Desktop
shortcuts. For a headless Server Core VM, use the `AgentOnly` profile.
Validate a backup restore while the service is stopped:

```powershell
& "$env:ProgramFiles\RoamSentinel\RoamSentinel.exe" `
  --restore-backup C:\Backups\RoamSentinel-backup.zip
```

For a headless agent-only machine:

```powershell
.\scripts\Publish-RoamSentinel.ps1 -Profile AgentOnly
.\scripts\Install-RoamSentinelService.ps1 `
  -PublishDirectory .\artifacts\publish\win-x64 `
  -Profile AgentOnly
```

For a university VM that will host Git repositories and CodeGate hooks:

```powershell
.\scripts\Invoke-OfflineVmReleaseRehearsal.ps1 `
  -FrameworkDependent `
  -Output .\artifacts\offline-vm-release
.\scripts\Install-RoamSentinelService.ps1 `
  -PublishDirectory .\artifacts\offline-vm-release `
  -Profile CodeGateVm
```

Use [Offline VM Release Checklist](docs/OFFLINE_VM_RELEASE_CHECKLIST.md)
before disconnecting the VM from the internet.

## 1. Install the .NET SDK

Install the .NET 10 SDK, then open a new PowerShell window and verify:

```powershell
dotnet --info
dotnet --list-sdks
```

The installed SDK list must include a `10.0` version.

## 2. Prepare the Repository

For the existing XAMPP layout:

```powershell
Set-Location C:\path\to\RoamSentinel
dotnet restore .\RoamSentinel.slnx
dotnet build .\RoamSentinel.slnx
dotnet test .\RoamSentinel.slnx --no-build
```

XAMPP Control Panel services do not need to be started. Do not create an Apache
virtual host for RoamSentinel.

## 3. Configure Local Authentication

The application fails closed for login when no token is configured. The
provided script generates an administrator-compatible response token in the
current Windows user's environment:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\Initialize-ResponseAuthorization.ps1
```

Close and reopen PowerShell so the new user environment variable is loaded.
The generated token is also placed on the clipboard.

For separate roles, generate unique tokens of at least 16 characters and store
them as user environment variables:

```powershell
[Environment]::SetEnvironmentVariable(
  "AccessControl__ViewerToken",
  "replace-with-a-unique-long-random-token",
  "User")
[Environment]::SetEnvironmentVariable(
  "AccessControl__AnalystToken",
  "replace-with-a-different-long-random-token",
  "User")
[Environment]::SetEnvironmentVariable(
  "AccessControl__AdministratorToken",
  "replace-with-another-long-random-token",
  "User")
```

Never commit tokens or API keys to `appsettings.json`.

## 4. Start RoamSentinel

Normal monitoring:

```powershell
.\scripts\start.ps1
```

Open `http://127.0.0.1:5117`.

For process termination, Firewall changes, startup changes, and some Defender
operations, start PowerShell with **Run as administrator**, then run the same
script.

Stop the application with `Ctrl+C`. From another shell, use:

```powershell
.\scripts\stop.ps1
```

## 5. Optional Threat-Intelligence Providers

Provider secrets use environment variables. Example:

```powershell
[Environment]::SetEnvironmentVariable(
  "ThreatIntel__VirusTotal__Enabled", "true", "User")
[Environment]::SetEnvironmentVariable(
  "ThreatIntel__VirusTotal__ApiKey", "your-api-key", "User")
```

Equivalent prefixes are:

- `ThreatIntel__AbuseIpDb__...`
- `ThreatIntel__AlienVaultOtx__...`
- `ThreatIntel__Misp__...`

Keep MISP TLS verification enabled. Use
`ThreatIntel__Misp__VerifyTls=false` only in an isolated test environment.

## 6. Storage and Permissions

Runtime state is created under:

- `data\roamsentinel.db`
- `Logs\app.log`
- `Logs\security.log`
- `Logs\response.log`
- `Logs\error.log`

The Windows account running RoamSentinel needs read/write access to `data` and
`Logs`. It does not need broad write access to Windows system directories.

## Port Conflict

If startup reports that `127.0.0.1:5117` is already in use:

```powershell
Get-NetTCPConnection -LocalPort 5117 -State Listen |
  Select-Object LocalAddress, LocalPort, OwningProcess
.\scripts\stop.ps1
.\scripts\start.ps1
```

The configured URL can be changed to another loopback port with
`RoamSentinel__BindUrl`, for example
`http://127.0.0.1:5120`. Non-loopback bind addresses are rejected.

## Updating

Stop the application, back up `data\roamsentinel.db`, update the source, then:

```powershell
dotnet restore .\RoamSentinel.slnx
dotnet test .\RoamSentinel.slnx
.\scripts\start.ps1
```

Database migrations run automatically before the HTTP server accepts requests.

## Publishing for an Installer

The current application can be staged as a self-contained Windows x64 build:

```powershell
dotnet publish .\RoamSentinel.csproj `
  --configuration Release `
  --runtime win-x64 `
  --self-contained true `
  --output .\artifacts\publish\win-x64
```

This produces installer input, not a finished installer. Code signing, service
hosting, secret provisioning, data-directory ACLs, upgrade/rollback behavior,
and uninstall data policy must be completed before commercial deployment. See
[`docs/INSTALLER_READINESS.md`](docs/INSTALLER_READINESS.md).

Prefer `scripts\Publish-RoamSentinel.ps1` for repeatable profile builds. It
writes `install-profile.json` and validates `Workstation`, `AgentOnly`, or
`CodeGateVm` output before installation.

## Offline VM Git Push Traceability

After installing RoamSentinel on a Windows university VM, CodeGate can be wired
into bare Git repositories without exposing the RS Agent dashboard remotely.

Install a `pre-receive` hook for a bare repository:

```powershell
& "$env:ProgramFiles\RoamSentinel\scripts\Install-CodeGateGitHook.ps1" `
  -Repository D:\Git\example.git `
  -Mode pre-receive `
  -Force
```

For audit-only repositories, use:

```powershell
& "$env:ProgramFiles\RoamSentinel\scripts\Install-CodeGateGitHook.ps1" `
  -Repository D:\Git\example.git `
  -Mode post-receive `
  -Force
```

Use `pre-receive` to reject pushes with a `block` verdict. Use
`post-receive` for audit-only recording. The installer writes
`hooks\roamsentinel-codegate.policy.json`; keep the default `blockVerdicts`
unless the repository has a reviewed local policy exception.

Validate the installed hook and policy file:

```powershell
& "$env:ProgramFiles\RoamSentinel\scripts\Test-CodeGateGitHookPolicy.ps1" `
  -Repository D:\Git\example.git `
  -ExpectedMode pre-receive
```

For periodic review across multiple repositories:

```powershell
& "$env:ProgramFiles\RoamSentinel\scripts\Test-CodeGateGitHookPolicy.ps1" `
  -Repository D:\Git\project-a.git,D:\Git\project-b.git `
  -ExpectedMode pre-receive `
  -Json
```

Record repository owner/security approval after review:

```powershell
& "$env:ProgramFiles\RoamSentinel\scripts\Approve-CodeGateGitHookPolicy.ps1" `
  -Repository D:\Git\example.git `
  -ApprovedBy "security-admin" `
  -Reason "Approved CodeGate policy for offline VM pilot" `
  -Ticket "RS-VM-001"
```

Require approval during validation:

```powershell
& "$env:ProgramFiles\RoamSentinel\scripts\Test-CodeGateGitHookPolicy.ps1" `
  -Repository D:\Git\example.git `
  -ExpectedMode pre-receive `
  -RequireApproval
```

Analyst users can export local CSV evidence from RS Console after login:

- CodeGate submissions
- Git push traceability
- Offline bundle freshness

The export endpoints remain loopback-only and require an Analyst-capable local
session:

```text
GET /api/v1/codegate/reports/submissions.csv
GET /api/v1/codegate/reports/git-pushes.csv
GET /api/v1/codegate/reports/offline-bundles.csv
```

The same Analyst session can open row-level CodeGate details in RS Console for
redacted findings, changed files, actors, revisions, and content hashes. These
detail views are read-only and use the loopback API.

## Periodic Offline Evidence Export

Use the local evidence export script to create a database backup, optional
CodeGate hook policy review JSON, and an evidence manifest with SHA-256 hashes:

```powershell
& "$env:ProgramFiles\RoamSentinel\scripts\Invoke-RoamSentinelEvidenceExport.ps1" `
  -OutputDirectory D:\RoamSentinelEvidence `
  -RetentionDays 30 `
  -Repository D:\Git\project-a.git,D:\Git\project-b.git `
  -ExpectedMode pre-receive `
  -RequireApproval
```

The script deletes previous `RoamSentinel-evidence-*` directories older than
`RetentionDays`. Store the output directory on a local protected volume or an
approved removable medium; it is not transmitted anywhere by RoamSentinel.

## Offline Rule and Advisory Bundles

For disconnected VMs, copy CodeGate rule, dependency-advisory, or IOC bundles
onto the machine and import them locally:

```powershell
& "$env:ProgramFiles\RoamSentinel\RoamSentinel.exe" `
  --import-codegate-bundle C:\Bundles\codegate-rules.json `
  --sha256 <expected-sha256>
```

The JSON manifest must include:

```json
{
  "component": "RS CodeGate",
  "bundleType": "codegate-rules",
  "name": "University VM baseline rules",
  "version": "2026.07.20",
  "schemaVersion": "1.0",
  "generatedAt": "2026-07-20T00:00:00Z",
  "source": "offline-admin",
  "signature": "signature-or-unsigned-marker"
}
```

Supported `bundleType` values are:

- `codegate-rules`
- `dependency-advisory-cache`
- `ioc-bundle`

The current pass validates and records bundle freshness. Later passes can bind
validated bundles to active scan policy.

See [`docs/OFFLINE_VM_DEPLOYMENT.md`](docs/OFFLINE_VM_DEPLOYMENT.md) for the
full university VM runbook.
