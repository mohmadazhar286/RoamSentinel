# Roadmap

This roadmap distinguishes implemented foundations from planned work. Ordering
may change based on test evidence and Windows platform constraints.

[RSAS v1.0](docs/RSAS-v1.0.md) is the architecture contract for future work.
Roadmap items must preserve its module boundaries, event model, security
controls, and versioned-contract direction or document an approved amendment.

[Broadened Scope](docs/BROADENED_SCOPE.md) sets the staged direction for
offline university VM operation, RS CodeGate intake auditing, future RS Control,
and RS Insider without exposing the current loopback dashboard remotely.

## Implemented Foundation

- Modular telemetry, detection, response, threat-intelligence, governance,
  dashboard, database, configuration, and logging boundaries
- Normalized Windows telemetry and resource-pressure views
- Database-backed detections, risk scoring, and ATT&CK mappings
- Local and external IOC enrichment adapters
- Controlled response actions with before/after evidence
- AI-agent catalog, trust policy, network risk, and enforcement safeguards
- SQLite migrations, structured logs, audit records, local RBAC, CSRF, input
  validation, and safe process execution
- Automated tests covering security rules, scoring, mappings, providers,
  governance, response logging, configuration, telemetry, and persistence
- v0.20 reliable local agent: Windows Service lifetime, ProgramData path
  separation, DPAPI secret abstraction, validated backup restore, endpoint
  contracts, dry-run response tests, and publish/install validation scripts
- Device Integrity inventory API and shared-console view covering drivers,
  installed software, registry persistence, monitored files, services,
  scheduled tasks, firewall profiles, network listeners, and PowerShell
  security posture
- Periodic RS Agent baseline collection with persisted, explainable Device
  Integrity change events
- Device Integrity findings projected from baseline changes with reviewable
  status transitions
- Offline CodeGate scan foundation with local file/repository scans, redacted
  evidence, persisted submissions/findings, and audit records
- Git push traceability foundation with repository, branch/ref, revision range,
  changed files, verdict, and audit records
- Offline CodeGate bundle import foundation with SHA-256 validation, freshness
  metadata, supported bundle types, and audit records
- CodeGate dashboard filters and Analyst-authenticated CSV report exports for
  submissions, Git push audits, and offline bundle freshness
- CodeGate finding-level drilldown for persisted submissions and Git push
  audits
- CodeGate Git hook installer with per-repository policy file support for
  offline VM repositories
- CodeGate Git hook policy review script for offline repository validation and
  JSON reporting
- CodeGate Git hook policy approval history for reviewed repository exceptions
- Profile-aware publish and install validation for `Workstation`, `AgentOnly`,
  and CodeGate-enabled VM packages
- CLI backup export and periodic local evidence export with SHA-256 manifest,
  scheduler health capture, CodeGate hook policy review capture, and retention
  cleanup
- Offline VM release rehearsal and final freeze checklist for the
  CodeGate-enabled university VM pilot
- Offline university VM deployment profile with readiness validation for
  publish output, installed service assets, CodeGate hooks, and ProgramData
  folders

## Version 1 Protection Scope

Version 1 is limited to Windows device integrity: processes, services, startup
entries, registry persistence, scheduled tasks, monitored file locations,
network connections, firewall state, PowerShell posture, drivers, and installed
software. User-behaviour analytics and RS CodeGate remain later phases.

Inventory does not imply a detection. New detection and response behavior must
be introduced as separately reviewed, explainable rules under RSAS v1.0.

## Broadened Scope Staging

The broadened product direction is:

1. **RS Agent** for reliable local Windows protection.
2. **RS CodeGate** for offline-capable code intake scanning and audit on a
   university VM.
3. **RS Insider** for explainable user/device risk events after stable local
   and code-intake event streams exist.
4. **RS Control** for future organization management, policy distribution, and
   evidence aggregation.

The current local dashboard must remain loopback-only. Organization management
requires RS Control rather than direct exposure of RS Agent.

## Near Term

- Run the offline VM release checklist on the actual university VM and record
  site-specific paths, repository owners, and token custody
- Windows integration tests for Defender, Firewall, services, and scheduled
  tasks on disposable Windows test machines
- Add code signing and installer wrapper for validated publish profiles
- Repository policy approval export and exception summary in RS Console
- Signed release builds and reproducible packaging
- Controlled service upgrade and rollback
- Activate validated offline rule/advisory bundles through reviewed CodeGate
  policy, with per-repository controls
- Backup retention UI and scheduled-task registration helper
- Rule import/export with schema validation and change review
- Notification channels for critical findings
- Improved alert correlation and duplicate suppression

## Security Platform Expansion

- ETW and Windows Event Log collectors
- Sysmon event ingestion with schema-aware normalization and health monitoring
- Sigma rule import, validation, translation, and versioned rule packs
- Optional Windows Filtering Platform or supported packet-capture integration
- File hashing and signature/publisher verification
- YARA scanning with signed rule packs, resource limits, and quarantine review
- Memory forensics through isolated acquisition and Volatility-compatible
  analysis workflows
- Tamper-evident audit export and external log forwarding
- IOC feed synchronization and MISP bidirectional workflows
- Baseline learning with explainable deviation scoring
- Multi-host architecture with mutually authenticated transport
- Cloud/XDR integrations for Microsoft Defender XDR, SIEM, ticketing, and
  evidence exchange

## RS CodeGate Expansion

- Server-side Git `pre-receive` and `post-receive` hook templates; initial
  Windows VM templates are implemented
- Manual CLI scan for local folders, ZIP extracts, USB imports, and cloned
  repositories; initial path scan foundation is implemented
- Secret detection with redacted evidence and non-reversible fingerprints
- Suspicious script and unexpected executable detection
- Offline dependency advisory cache import for common package ecosystems
- Offline bundle freshness display and import audit; initial metadata import is
  implemented
- CodeGate verdict lifecycle: `allow`, `warn`, `block`, `needs_review`
- Repository, branch, commit, actor, file-hash, policy-version, and verdict
  audit records
- Exportable reports for offline university VM review

## AI-Agent Governance Expansion

- Per-agent capability declarations and approved workspace scopes
- File, process, command, and network activity correlation
- Approval receipts for sensitive agent actions
- Provider/model identity and plugin/MCP inventory
- Agent policy templates and organization-wide distribution
- Secret-access detection without recording secret values
- Mobile companion inventory and protected tethering workflows
- AI Security Copilot for evidence-grounded triage, policy explanation, query
  assistance, and human-approved response planning

## Product Readiness

- Installer and uninstaller
- Code signing
- Accessibility and localization review
- Performance soak tests and telemetry-volume benchmarks
- Backup and disaster-recovery validation
- Administrator policy reference and support bundle generation
- Privacy, licensing, support, and vulnerability-disclosure policies

## Non-Goals Until Re-Architected

- Exposing the current localhost dashboard directly to a LAN or the internet
- Decrypting TLS traffic
- Claiming complete malware prevention or forensic completeness
- Automatically blocking shared runtime hosts without process-level isolation
