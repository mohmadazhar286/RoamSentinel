# Architecture Audit

> Historical note: this document describes the pre-PASS 2 prototype. The current modular architecture is documented in `docs/MODULAR_ARCHITECTURE.md`.

## Scope

PASS 1 audited the repository without changing product behavior. The runtime fix aligned `launchSettings.json` with the application's existing `127.0.0.1:5117` binding.

## Repository Inventory

| Area | Current implementation |
|---|---|
| Runtime entry point | `Program.cs` top-level ASP.NET Core application |
| Project | `RoamSentinel.csproj`, targeting `net10.0-windows`; assembly and namespace are `RoamSentinel` |
| Dashboard | Static `wwwroot/index.html`, `wwwroot/app.js`, and `wwwroot/styles.css` |
| Configuration | `appsettings.json`, `appsettings.Development.json`, `Properties/launchSettings.json` |
| Operations | `scripts/start.ps1` and `scripts/stop.ps1` |
| Runtime state | `data/events.jsonl`, `data/agent-policy.json`, `data/ip-blocks.json` |
| Database | None |
| Tests | None |
| Packaging/service | No installer, Windows Service, updater, or code-signing configuration |

`bin/`, `obj/`, `data/`, and runtime logs are git-ignored. The repository is on `main` and was clean before this audit.

## Current Logical Modules

All backend modules currently live in `Program.cs`:

| Module | Responsibility |
|---|---|
| HTTP endpoints | Maps dashboard queries and response actions directly to static services |
| `TelemetryService` | TCP/UDP snapshots, process inventory, startup registry entries, services, scheduled tasks, Defender status, PowerShell execution |
| `ResourceMonitor` | Physical-memory status and sampled per-process CPU usage |
| `DetectionEngine` | Hard-coded risk scoring and alert generation |
| `EventStore` | In-memory alert index plus append-only JSONL persistence and purge |
| `AgentPolicyStore` | JSON persistence for authorized and blocked agent executable paths |
| `IpBlockStore` | JSON persistence for IP blocks created by the application |
| `FirewallService` | Creates/removes Windows Firewall program and IP rules through PowerShell |
| `PolicyCatalog` | Static human-readable policy descriptions |
| Dashboard JavaScript | Polling, rendering, confirmations, and API actions |

## Current Data Flow

```text
Browser (8-second polling)
  -> ASP.NET minimal API endpoint
    -> TelemetryService / ResourceMonitor
      -> PowerShell cmdlets, Process API, Registry, filesystem, Defender
    -> DetectionEngine
      -> EventStore
        -> data/events.jsonl
    -> JSON response
  -> DOM rendering

Response action
  -> API endpoint
    -> Defender / Firewall / Process.Kill
    -> AgentPolicyStore or IpBlockStore
    -> EventStore action record
```

The normal dashboard refresh requests `/api/summary`, `/api/performance`, and the active view endpoint. Several endpoints independently recollect the same connections, processes, Defender state, and persistence data.

## Existing Security Actions

- Start Defender quick, full, or signature-update-plus-full scans.
- Stop a process tree by PID.
- Add inbound/outbound remote-IP Windows Firewall blocks.
- Restore application-created IP blocks.
- Add/remove outbound executable-path firewall blocks for detected AI/developer agents.
- Authorize, block, or restore agent executable paths.
- Purge retained application events after review.

## Current Risks

### High

1. **Privileged control plane has no authentication or authorization.** It binds to loopback, but any local process able to call the API can request firewall changes, process termination, scans, or log purge.
2. **Collection is request-driven and duplicated.** A single UI refresh can launch multiple PowerShell processes and repeat process/network/persistence scans. This increases latency and can contribute to the system load the product is intended to diagnose.
3. **No durable security event model.** JSONL records have no schema version, integrity protection, occurrence count, lifecycle state, ATT&CK mapping, evidence references, or migration mechanism.
4. **Errors are frequently swallowed.** Several telemetry methods convert access or parsing failures into empty collections. The dashboard can therefore display missing telemetry as an apparently clean state.
5. **Response state is not transactional.** Firewall changes and JSON policy updates can diverge after partial failures or interruption.

### Medium

1. Detection logic is embedded as hard-coded process names, paths, ports, and thresholds.
2. Agent identity is based on name/path substrings. It does not verify publisher, signature, hash, package identity, parent process, command line, or requested capability.
3. Windows Store application paths are versioned, so path-based authorization and firewall rules can become stale after updates.
4. Event deduplication uses a deterministic alert hash and preserves only the first occurrence in memory. Repeated activity and frequency are lost.
5. The JSONL event file is loaded into memory at startup and has no automatic rotation or size bound.
6. Local files can contain sensitive executable paths, IPs, and behavioral history but are not encrypted or ACL-hardened by the application.
7. PowerShell with `ExecutionPolicy Bypass` is the main integration mechanism. It is slow, difficult to constrain, and weakens observability of failures.
8. CPU sampling uses a static PID cache without eviction or process-start identity, creating PID-reuse and unbounded-cache risks.

## Fragile Areas

- `Program.cs` combines composition, transport, domain logic, Windows integration, persistence, and DTOs in one file.
- Endpoint handlers directly coordinate low-level effects and cannot be tested without the real machine.
- Static mutable stores and global caches prevent dependency isolation and deterministic tests.
- The frontend assumes all endpoints are available and performs overlapping polling without cancellation, backpressure, or stale-request protection.
- Scheduled-task XML and registry scans run synchronously on request threads.
- Process termination protects only the current application PID; there is no protected-process policy or response approval model.
- Agent authorization reports success even if removing a firewall block fails.
- IP restore depends on application-side JSON matching actual firewall state.
- Project, package, and assembly identity should remain consistently RoamSentinel.
- Configuration is mostly hard-coded; `appsettings` is not used for ports, collection intervals, retention, thresholds, or feature flags.

## Missing Abstractions

The next refactor should introduce explicit contracts before adding new security features:

- `ITelemetryCollector<T>` and immutable telemetry envelopes with source, timestamp, quality, and collection errors.
- Background collection scheduler and bounded snapshot cache, independent of HTTP requests.
- Versioned event/evidence model with finding lifecycle and occurrence tracking.
- `IDetectionRule` plus rule metadata: severity, confidence, ATT&CK technique, data requirements, and remediation.
- Threat-intelligence provider interface with indicator provenance, TTL, confidence, and local caching.
- `IResponseAction` with authorization, dry-run, idempotency, audit, rollback, and result state.
- Repository interfaces for events, policies, agent identities, response state, and migrations.
- Windows integration adapters for Defender, Firewall, processes, Event Log/ETW, registry, services, and scheduled tasks.
- Agent identity and capability policy model based on signed identity and requested resource access, not only executable path.
- API authentication/authorization boundary and anti-CSRF/local-client protections.
- Health/diagnostic model that distinguishes "clean" from "collector unavailable."
- Configuration/options classes with validation and environment-specific overrides.
- Unit, integration, contract, and Windows-host test projects.

## SOTA Foundation Gaps

Not currently present:

- MITRE ATT&CK technique/tactic mapping.
- Sigma/YARA or equivalent rule ingestion.
- Threat-intelligence feeds, IOC matching, reputation, or indicator expiry.
- ETW, Windows Event Log, Sysmon, AMSI, DNS, file-integrity, or packet telemetry.
- Normalized process tree, command-line, signer, hash, user/session, and network-flow entities.
- Case management, finding status, suppression, exception expiry, evidence export, or audit integrity.
- Service isolation, tamper protection, least-privilege split, secure update channel, installer, or code signing.
- AI-agent capability governance for files, shell, network, credentials, clipboard, browser, or external tools.

## Stabilization Verification

- `dotnet build` succeeds with zero warnings and zero errors.
- The application starts on `http://127.0.0.1:5117`.
- `/`, `/api/policies`, and `/api/defender` return HTTP 200.
- Runtime configuration now launches the same URL the application binds to.
