# Commercial Readiness Review

## Product Identity

The commercial and technical identity is **RoamSentinel**. Assembly, package,
file metadata, and RS component names use this identity consistently.

## Dead-Code Review

Removed:

- the superseded root `Program.cs`
- duplicate static assets under `wwwroot`

Retained intentionally:

- `JsonFileStore`, used by one-time legacy JSON import
- `LegacyFirewallRulePrefix`, used to remove Firewall rules created by earlier
  RoamSentinel builds
- legacy read endpoints, still consumed by current dashboard workflows and
  retained for API compatibility

Compiler result: zero warnings. Further removal should be driven by endpoint
contract and migration telemetry, not filename age.

## Commercial Foundations Present

- modular service boundaries
- versioned SQLite migrations
- local role-based control plane
- structured and database audit records
- controlled response evidence
- externalized secrets
- automated security and persistence tests
- consistent database export
- installation, administration, architecture, security, testing, roadmap, and
  change documentation

## Release Blockers

- placeholder license requires legal review
- binaries and installer are not code-signed
- no finished MSI/MSIX installer
- no Windows service deployment or recovery policy
- no protected production secret store
- no automatic signed update channel or rollback manager
- no formal privacy, support, vulnerability disclosure, or SLA documents
- no third-party license inventory or software bill of materials
- no independent penetration test
- no long-duration performance and database-growth qualification

## Backup Export

The Settings view exposes an Administrator-only export. It uses SQLite online
backup to create a consistent database copy and packages it with a manifest and
restore instructions. Credentials and API keys are not exported. The action is
audited.

## Product Decision

The system is suitable as a versioned local preview and engineering pilot. It
is not yet ready for unrestricted commercial distribution until the listed
release blockers are closed.
