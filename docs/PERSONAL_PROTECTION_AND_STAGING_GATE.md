# RoamSentinel Personal Protection and Staging Gate

This document defines the minimal protection posture for using RoamSentinel on
personal Windows devices and staging VMs.

RoamSentinel does not replace Sophos, Microsoft Defender, backups, patching, or
disk encryption. Its local value is visibility, controlled response, and
deployment gating before untrusted application code is promoted.

## Personal device baseline

Use RS as a local control plane for:

- Microsoft Defender scan launch;
- Windows Firewall IP block and restore;
- AI/developer-agent executable network policy review;
- Device Integrity baseline change review;
- CodeGate scans before trusting downloaded, cloned, copied, or staged code;
- MobileBridge companion telemetry experiments.

RS intentionally does not perform autonomous destructive remediation in this
profile. Deletion, quarantine, process termination, and firewall changes remain
authenticated, authorized, CSRF-protected where browser-initiated, logged, and
audited.

The local profile API is:

```text
GET /api/v1/device-shield/personal-protection
```

## Staging deployment gate

Use the staging gate before deploying a local app, university VM app, imported
ZIP, USB copy, or Git working tree:

```powershell
& "$env:ProgramFiles\RoamSentinel\scripts\Invoke-RoamSentinelStagingGate.ps1" `
  -Path C:\Staging\incoming-app `
  -Revision release-candidate
```

For stricter staging behavior, fail on warnings too:

```powershell
& "$env:ProgramFiles\RoamSentinel\scripts\Invoke-RoamSentinelStagingGate.ps1" `
  -Path C:\Staging\incoming-app `
  -Revision release-candidate `
  -FailOnWarn
```

The gate currently blocks or warns on local, explainable indicators including:

- hardcoded credentials and private keys;
- cloud access tokens;
- suspicious PowerShell or encoded execution;
- remote installer pipes such as `curl ... | bash`;
- destructive deployment commands;
- package install lifecycle commands that invoke shells or network tools;
- broad or insecure dependency declarations;
- unexpected executables and scripts in staged code;
- privileged/root container deployment patterns;
- sensitive data or credential fields in deployment artifacts.

The result is a Sophos-like staging experience in one narrow sense: risky
artifacts are stopped before promotion. It is not malware emulation, sandboxing,
or reputation-based antivirus.
