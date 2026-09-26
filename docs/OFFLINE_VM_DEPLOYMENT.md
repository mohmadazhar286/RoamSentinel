# RoamSentinel Offline University VM Deployment

This guide defines the supported deployment profile for a university-allotted
Windows VM that will be configured once, then operated with no internet access.

The profile is intended for:

- local RS Agent protection of the VM;
- RS CodeGate scanning of pushed or imported code;
- repository traceability for multiple contributors;
- local evidence retention and export;
- offline operation after initial configuration.

It is not a remote management profile. The RS Agent dashboard must remain bound
to loopback (`127.0.0.1`) and must not be reverse-proxied to the university LAN.

Use [Offline VM Release Checklist](OFFLINE_VM_RELEASE_CHECKLIST.md) as the
final freeze gate.

## Components Used

| Component | VM role |
|---|---|
| RS Agent | Runs as the Windows Service and records endpoint evidence. |
| RS Console | Optional local dashboard over RDP/Desktop Experience only. |
| RS CodeGate | Scans code paths, Git pushes, and offline bundles. |
| SQLite database | Stores telemetry, findings, CodeGate submissions, Git audits, and bundle freshness. |
| ProgramData | Stores mutable data, logs, and configuration. |

## Pre-Freeze Checklist

Complete these steps before disconnecting the VM from the internet:

1. Install Windows updates and reboot.
2. Update Microsoft Defender signatures.
3. Install Git if the VM will host repositories.
4. Install the .NET runtime/SDK needed by the published package, or publish
   RoamSentinel self-contained.
5. Publish RoamSentinel:

   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   .\scripts\Invoke-OfflineVmReleaseRehearsal.ps1 `
     -FrameworkDependent `
     -Output .\artifacts\offline-vm-release
   ```

6. Validate the publish output if you did not use the rehearsal script:

   ```powershell
   .\scripts\Test-PublishOutput.ps1 `
     -PublishDirectory .\artifacts\offline-vm-release `
     -Profile CodeGateVm
   .\scripts\Test-OfflineVmReadiness.ps1 `
     -PublishDirectory .\artifacts\offline-vm-release `
     -ExpectedProfile CodeGateVm
   ```

7. Install the service:

   ```powershell
   .\scripts\Install-RoamSentinelService.ps1 `
     -PublishDirectory .\artifacts\offline-vm-release `
     -Profile CodeGateVm
   ```

8. Validate installed readiness:

   ```powershell
   & "$env:ProgramFiles\RoamSentinel\scripts\Test-OfflineVmReadiness.ps1" `
     -Installed `
     -RequireService
   ```

9. Generate and store separate Viewer, Analyst, and Administrator tokens.
10. Import offline CodeGate bundles:

    ```powershell
    & "$env:ProgramFiles\RoamSentinel\RoamSentinel.exe" `
      --import-codegate-bundle C:\Bundles\codegate-rules.json `
      --sha256 <expected-sha256>
    ```

11. Test CodeGate with a clean sample and a blocked sample.
12. Export a backup and test restore on a disposable copy.
13. Create a periodic evidence export folder and validate retention.

## Runtime Paths

Installed binaries:

```text
%ProgramFiles%\RoamSentinel
```

Mutable state:

```text
%ProgramData%\RoamSentinel\data
%ProgramData%\RoamSentinel\logs
%ProgramData%\RoamSentinel\config
```

Do not store mutable runtime state inside the application directory.

## Git Repository Hook Setup

For each bare repository hosted on the VM, install a hook and policy file:

```powershell
& "$env:ProgramFiles\RoamSentinel\scripts\Install-CodeGateGitHook.ps1" `
  -Repository D:\Git\example.git `
  -Mode pre-receive `
  -Force
```

Use:

- `pre-receive` when blocked CodeGate verdicts should reject the push;
- `post-receive` when all pushes should be accepted but audited.

The installer writes:

```text
D:\Git\example.git\hooks\roamsentinel-codegate.policy.json
```

Default policy:

```json
{
  "schemaVersion": "1.0",
  "mode": "pre-receive",
  "actor": "",
  "roamSentinelExe": "C:\\Program Files\\RoamSentinel\\RoamSentinel.exe",
  "blockVerdicts": ["block"]
}
```

Treat this file as the per-repository review point. Do not broaden
`blockVerdicts` to include `warn` without a repository owner decision because
that converts advisory findings into push rejection.

Validate the installed hook and policy:

```powershell
& "$env:ProgramFiles\RoamSentinel\scripts\Test-CodeGateGitHookPolicy.ps1" `
  -Repository D:\Git\example.git `
  -ExpectedMode pre-receive
```

For a reviewable JSON report:

```powershell
& "$env:ProgramFiles\RoamSentinel\scripts\Test-CodeGateGitHookPolicy.ps1" `
  -Repository D:\Git\project-a.git,D:\Git\project-b.git `
  -ExpectedMode pre-receive `
  -Json
```

After repository owner/security review, record approval:

```powershell
& "$env:ProgramFiles\RoamSentinel\scripts\Approve-CodeGateGitHookPolicy.ps1" `
  -Repository D:\Git\example.git `
  -ApprovedBy "security-admin" `
  -Reason "Approved CodeGate policy for offline VM pilot" `
  -Ticket "RS-VM-001"
```

Then require approval in the final freeze check:

```powershell
& "$env:ProgramFiles\RoamSentinel\scripts\Test-CodeGateGitHookPolicy.ps1" `
  -Repository D:\Git\example.git `
  -ExpectedMode pre-receive `
  -RequireApproval
```

The hook records:

- actor;
- repository path and repository name;
- ref and branch;
- old and new revision;
- changed files;
- CodeGate submission ID;
- verdict and risk score.

## Offline Bundle Format

Bundle manifests must be JSON and include:

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

Supported bundle types:

- `codegate-rules`;
- `dependency-advisory-cache`;
- `ioc-bundle`.

The importer computes SHA-256 locally and compares it with the operator-supplied
expected hash. The current implementation records freshness and audit evidence;
activation of imported rules is a later policy pass.

## Operating Model After Network Freeze

After internet access is disabled:

- use RDP/local access to view RS Console;
- keep the dashboard on loopback only;
- use CodeGate CLI and Git hooks locally;
- export evidence through authenticated backup/report flows;
- use Analyst-authenticated CodeGate CSV exports for submissions, Git push
  traceability, and offline bundle freshness during periodic review;
- use Analyst-authenticated CodeGate detail views to review redacted findings,
  changed files, actors, revisions, and content hashes locally;
- run periodic local evidence exports with backup, scheduler health,
  policy-review JSON, and SHA-256 manifest retention;
- import updated rule/advisory/IOC bundles manually;
- record the update date of every imported bundle.

## Validation Commands

Check service:

```powershell
Get-Service RoamSentinel
```

Check readiness:

```powershell
& "$env:ProgramFiles\RoamSentinel\scripts\Test-OfflineVmReadiness.ps1" `
  -Installed `
  -RequireService
```

Run a manual CodeGate scan:

```powershell
& "$env:ProgramFiles\RoamSentinel\RoamSentinel.exe" `
  --codegate-scan D:\Repos\incoming `
  --source manual-vm-check `
  --revision working-copy
```

Export CodeGate CSV evidence from RS Console after Analyst login, or call the
loopback endpoints from the local VM session:

```text
http://127.0.0.1:5117/api/v1/codegate/reports/submissions.csv
http://127.0.0.1:5117/api/v1/codegate/reports/git-pushes.csv
http://127.0.0.1:5117/api/v1/codegate/reports/offline-bundles.csv
```

Run a periodic local evidence export:

```powershell
& "$env:ProgramFiles\RoamSentinel\scripts\Invoke-RoamSentinelEvidenceExport.ps1" `
  -OutputDirectory D:\RoamSentinelEvidence `
  -RetentionDays 30 `
  -Repository D:\Git\project-a.git,D:\Git\project-b.git `
  -ExpectedMode pre-receive `
  -RequireApproval
```

Each run creates a `RoamSentinel-evidence-*` directory containing a backup ZIP,
`scheduler-status.json`, optional CodeGate hook policy review JSON, and
`evidence-manifest.json` with SHA-256 hashes. Older evidence directories are
deleted according to `RetentionDays`.

Export scheduler health directly when validating the agent without opening RS
Console:

```powershell
& "$env:ProgramFiles\RoamSentinel\RoamSentinel.exe" `
  --scheduler-status `
  --json `
  --output D:\RoamSentinelEvidence\scheduler-status.json
```

## Security Constraints

- Do not bind RoamSentinel to `0.0.0.0`, a LAN IP, or a public IP.
- Do not reverse-proxy the RS Agent dashboard.
- Do not share Administrator tokens with contributors.
- Do not store raw secrets from scanned repositories in reports.
- Do not make imported offline bundles active without reviewed policy.
- Do not treat offline vulnerability data as current unless freshness is
  documented.

## Exit Criteria for the VM Profile

The VM profile is ready when:

- RS Agent service starts automatically;
- ProgramData folders exist;
- RS Console is reachable locally only;
- CodeGate CLI scans work offline;
- Git hook templates are present;
- per-repository CodeGate hook policy files can be installed;
- per-repository CodeGate hook policy files can be validated and exported as
  JSON;
- per-repository CodeGate hook policy files have approval history before the
  final freeze check;
- offline bundles can be imported and shown in freshness views;
- CodeGate CSV reports can be exported by an Analyst locally;
- CodeGate submission and Git push detail views show persisted evidence
  locally;
- backup export/restore has been tested;
- periodic evidence export creates a manifest and applies retention;
- offline VM release rehearsal passes and writes
  `offline-vm-release-rehearsal.json`;
- no current workflow requires internet access after freeze.
