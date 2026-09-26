# Installer Readiness

## Current Packaging Baseline

- Product: `RoamSentinel`
- Version: `0.20.0-preview`
- Target: `net10.0-windows`
- Preferred runtime: Windows x64
- Web host: loopback ASP.NET Core Kestrel
- Data store: local SQLite
- Native dependencies: PowerShell, Windows Firewall, Microsoft Defender

A release publish must be staged with an explicit profile:

```powershell
.\scripts\Publish-RoamSentinel.ps1 -Profile Workstation
.\scripts\Publish-RoamSentinel.ps1 -Profile AgentOnly
.\scripts\Publish-RoamSentinel.ps1 -Profile CodeGateVm
```

Every publish output includes `install-profile.json` and must pass
`scripts\Test-PublishOutput.ps1` before installation. The future MSI or
enterprise installer should consume this manifest rather than infer package
shape from directory contents.

## Installer Responsibilities

The future installer must:

1. Verify supported Windows versions and architecture.
2. Install signed application binaries under `Program Files`.
3. Create a writable, access-controlled data directory under
   `ProgramData\RoamSentinel`.
4. Keep binaries, configuration, logs, and database in separate directories.
5. Provision access tokens without writing secrets into installer logs.
6. Register a Windows service or approved per-user startup mechanism.
7. Add only the minimum required local Firewall behavior.
8. Preserve the database during upgrade and support rollback.
9. Offer explicit retain/delete choices during uninstall.
10. Register product name, version, publisher, support URL, and uninstall data.

## Release Gates

The following are required before commercial installation:

- Authenticode certificate and signed binaries, scripts, installer, and update
  packages
- reviewed commercial license and third-party notices
- Windows service lifecycle and recovery behavior
- protected secret storage, preferably DPAPI or Windows Credential Manager
- installer upgrade, downgrade, repair, and rollback tests
- data ACL and least-privilege validation
- offline and online installation tests
- backup compatibility test before every schema upgrade
- vulnerability scanning and software bill of materials
- clean uninstall and retained-data verification
- release provenance, checksums, and reproducible build records

## Recommended Packaging Decision

Use WiX Toolset for an enterprise MSI when Windows service installation,
ProgramData ACLs, repair, and managed deployment are priorities. MSIX is an
alternative only after confirming that Defender, Firewall, service, and
ProgramData operations fit its packaging constraints.

Do not distribute the current development folder as an installer.
