# RoamSentinel Offline VM Release Checklist

Use this checklist before disconnecting a university VM from the internet.

## 1. Build Rehearsal

From the source checkout:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\Invoke-OfflineVmReleaseRehearsal.ps1 `
  -FrameworkDependent `
  -Output .\artifacts\offline-vm-release
```

Expected result:

- Release build succeeds.
- Automated tests pass.
- `CodeGateVm` publish succeeds.
- `install-profile.json` reports `profile: CodeGateVm`.
- offline VM readiness passes.
- `offline-vm-release-rehearsal.json` is written to the publish directory.

## 2. Installation

Install from the rehearsed publish output using an elevated PowerShell:

```powershell
.\scripts\Install-RoamSentinelService.ps1 `
  -PublishDirectory .\artifacts\offline-vm-release `
  -Profile CodeGateVm
```

Validate:

```powershell
& "$env:ProgramFiles\RoamSentinel\scripts\Test-OfflineVmReadiness.ps1" `
  -Installed `
  -ExpectedProfile CodeGateVm `
  -RequireService
```

## 3. Local Access and Authentication

- Confirm RS Console opens only through `http://127.0.0.1:5117`.
- Create separate Viewer, Analyst, and Administrator tokens.
- Confirm write actions require login and CSRF-protected browser requests.
- Do not expose the loopback dashboard through a reverse proxy.

## 4. CodeGate Repository Setup

For every bare Git repository:

```powershell
& "$env:ProgramFiles\RoamSentinel\scripts\Install-CodeGateGitHook.ps1" `
  -Repository D:\Git\example.git `
  -Mode pre-receive `
  -Force

& "$env:ProgramFiles\RoamSentinel\scripts\Approve-CodeGateGitHookPolicy.ps1" `
  -Repository D:\Git\example.git `
  -ApprovedBy "security-admin" `
  -Reason "Approved CodeGate policy for offline VM pilot" `
  -Ticket "RS-VM-001"

& "$env:ProgramFiles\RoamSentinel\scripts\Test-CodeGateGitHookPolicy.ps1" `
  -Repository D:\Git\example.git `
  -ExpectedMode pre-receive `
  -RequireApproval
```

## 5. Evidence Export

Run one evidence export before freezing network access:

```powershell
& "$env:ProgramFiles\RoamSentinel\scripts\Invoke-RoamSentinelEvidenceExport.ps1" `
  -OutputDirectory D:\RoamSentinelEvidence `
  -RetentionDays 30 `
  -Repository D:\Git\example.git `
  -ExpectedMode pre-receive `
  -RequireApproval
```

Confirm the export contains:

- a backup ZIP;
- `evidence-manifest.json`;
- CodeGate hook policy review JSON when repositories are supplied.

## 6. Offline Freeze Gate

Freeze the VM only after all checks are true:

- Windows updates and Defender signatures are current.
- RoamSentinel service starts automatically.
- ProgramData folders exist.
- CodeGate hooks are installed and approval-required validation passes.
- backup restore has been tested on a disposable copy.
- evidence export has been tested.
- no workflow depends on internet after the freeze.
