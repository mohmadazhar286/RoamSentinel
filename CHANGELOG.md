# Changelog

All notable changes are recorded here. The project does not yet publish signed
versioned releases; entries describe the current development baseline.

## Unreleased

### Added

- Module experience manifest endpoint and contract-driven RS Console workspace
  shell for future module-wise UI isolation without changing existing
  `/api/modules` compatibility
- Protection Scheduler module registration, module-owned scheduler experience
  endpoint, and shared-console scheduler health surface
- Scheduler status CLI export and inclusion of scheduler health in periodic
  offline evidence bundles
- Initial Version 1 Device Integrity inventory and `/api/v1/device-integrity`
  endpoint for drivers, installed software, registry persistence, monitored
  files, and PowerShell security posture
- Expanded Device Integrity baselines for local services, scheduled tasks,
  firewall profiles, and network listeners
- Device Integrity findings projected from baseline events with reviewable
  status updates and audit records
- Offline RS CodeGate path-scan foundation with persisted submissions,
  findings, verdicts, content hashes, redacted evidence, CLI support, and API
  access
- Git push traceability foundation with persisted repository, branch/ref,
  revision, changed-file, verdict, and audit records plus Windows VM hook
  templates
- Offline CodeGate bundle import foundation with SHA-256 validation, supported
  bundle types, freshness display, CLI/API access, and audit records
- Analyst-authenticated CodeGate CSV exports and shared-console filters for
  submissions, Git push audits, and offline bundle freshness
- Analyst-authenticated CodeGate drilldown endpoints and shared-console detail
  panel for submission findings, Git push revisions, actors, and changed files
- CodeGate Git hook installer script with per-repository policy file support
  for offline VM repositories
- CodeGate Git hook policy review script for offline validation and JSON
  reporting across repositories
- CodeGate Git hook policy approval script with local approval metadata and
  append-only approval history in each repository policy file
- Profile-aware publish and install validation for `Workstation`, `AgentOnly`,
  and CodeGate-enabled VM packages with `install-profile.json`
- CLI backup export plus periodic local evidence export script with SHA-256
  manifest, CodeGate hook policy review capture, and age-based retention
- MobileBridge local enrollment and heartbeat helper scripts, plus offline RS
  Console QR pairing payloads and command instructions that consume generated
  pairing codes without exposing the loopback-only service
- Minimal personal-device protection profile API and staging deployment gate
  script for Sophos-like local blocking of risky deployment artifacts before
  promotion
- Offline VM release rehearsal script and final freeze checklist for the
  CodeGate-enabled university VM pilot
- Offline university VM deployment profile with readiness script, publish
  validation for CodeGate hook assets, and deployment runbook
- Shared-console Device Integrity workspace
- Agent-hosted periodic Device Integrity monitor, SQLite baselines, and
  explainable added/changed/removed event history
- RSAS v1.0, the formal system architecture specification and implementation
  contract for future platform work
- Broadened scope document for offline university VM operation, RS CodeGate
  intake auditing, future RS Control, and RS Insider staging
- Shared light/dark theme tokens with system preference and manual selection
- Visible Browser Console, Desktop Console, and Service Agent mode indicators
- Device Shield, RS CodeGate, and RS Insider module registrations and contracts
- Theme contrast, RS Console route-parity, and module-registration tests
- RS logo placeholder in the shared console header

### Changed

- RS Console now hosts the complete public dashboard instead of a reduced UI
- Browser Console and RS Console now use identical API endpoints and features
- Project, package, and UI identity now use RoamSentinel and RS component names

### Removed

- Reduced console-only dashboard implementation
- Previous product identity and dual-brand metadata

## 0.20.0-preview - 2026-07-06

### Added

- Windows Service hosting with automatic service recovery installation scripts
- `%ProgramData%\RoamSentinel` data, logs, and configuration separation
- Runtime path service and DPAPI machine-scoped local secret store
- SHA-256 and SQLite-integrity-validated backup restore API and CLI
- ASP.NET test-host endpoint contracts and response dry-run coverage
- Publish-output validation and service install/uninstall scripts
- Native WPF management console and combined workstation/server-VM installer
  profile, with an optional headless agent-only profile

### Changed

- Product and assembly version advanced to `0.20.0-preview`
- Relative database and logging paths now resolve inside their dedicated
  ProgramData directories

### Added

- Consolidated installation, architecture, security, administration, testing,
  roadmap, and project documentation
- Windows/XAMPP workspace instructions with Kestrel hosting clarification
- Product and assembly version `0.15.0-preview` (previous baseline)
- RoamSentinel branding metadata
- Administrator-only ZIP backup export with SQLite snapshot, manifest, restore
  instructions, audit record, and dashboard control
- Commercial license placeholder and installer-readiness assessment
- Explicit roadmap for Sysmon, Sigma, YARA, memory forensics, Cloud/XDR, and AI
  Security Copilot

### Removed

- Superseded monolithic entry point and duplicate `wwwroot` dashboard assets;
  the active composition root is `app\Program.cs` and static root is `public`

## 2026-07-05 - Security Platform Foundation

### Added

- Modular application boundaries for telemetry, detection, response, threat
  intelligence, AI-agent governance, dashboard, database, configuration, and
  logs
- SQLite migrations and repositories for telemetry, events, rules, ATT&CK,
  indicators, agents, response evidence, settings, and audit records
- Process, network, startup, scheduled-task, service, Defender, Firewall,
  resource, agent, suspicious-path, and process-lineage telemetry
- Weighted rule engine with five severity levels and ATT&CK mappings
- Local IOC management and adapters for VirusTotal, AbuseIPDB, AlienVault OTX,
  and MISP
- Controlled Defender, Firewall, process, file, startup, and alert response
  actions
- Known AI-agent catalog, trust states, network observations, risk scoring, and
  shared-host safeguards
- Ten-section operational dashboard and compatibility read endpoints
- Structured application, security, response, and error logs
- Local sessions, Viewer/Analyst/Administrator roles, CSRF protection, input
  validation, security headers, elevation checks, and safe process execution
- Automated coverage for detection rules, risk boundaries, MITRE mappings,
  threat providers, agent registry, response logging, database constraints,
  security hardening, configuration, and telemetry

### Changed

- Product identity standardized as RoamSentinel
- Static UI moved from `wwwroot` to `public`
- Legacy JSON state is imported once into SQLite and retained as backup
- Defender scans launch asynchronously so full scans do not block the dashboard
- Scheduled-task enumeration tolerates Windows-protected directories
- Empty AI-agent observation cycles now mark previously running agents stopped

### Security

- Dashboard binding is validated as loopback-only
- Write actions fail closed without configured authentication
- Response attempts retain actor, result, error, and before/after evidence
- Secrets are externalized to environment configuration
