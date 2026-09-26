# Modular Architecture

## Module Boundaries

| Module | Owns | Must not own |
|---|---|---|
| `app` | Composition root, application orchestration, command endpoint registration | Windows implementation details or persistence formats |
| `Core` | Domain records and interfaces | Infrastructure implementations |
| `Telemetry` | Read-only Windows collection, normalized snapshots, process lineage, and inventory sampling | Risk scoring, trust decisions, or response actions |
| `Detection` | Database-backed rule evaluation, weighted scoring, findings, severity, and ATT&CK projection | Collection, privileged remediation, or dashboard rendering |
| `Response` | Defender, Firewall, and process response actions | Dashboard rendering or detection policy |
| `ThreatIntel` | Indicator enrichment contract and providers | Detection decisions or response actions |
| `AgentGovernance` | AI-agent identity classification and trusted/blocked policy | Firewall or process actions |
| `Dashboard` | Read-only HTTP endpoints for dashboard data | POST actions or privileged operations |
| `Database` | SQLite connection handling, migrations, repositories, legacy import, and audit persistence | Detection and response policy |
| `Config` | Runtime options and displayed policy catalog | Operational state |
| `Logs` | Audit/event logging service | Storage format details |
| `public` | Static HTML, CSS, and browser-side API client | Direct Windows access |
| `tests` | Unit and later integration/contract tests | Production runtime code |

## Runtime Flow

```text
public dashboard
  -> Dashboard GET endpoints
    -> SecuritySnapshotService
      -> Telemetry (raw observations)
      -> AgentGovernance (agent identity/trust)
      -> Detection (risk and findings)
    -> Logs / Database (review data)

public dashboard command
  -> app/Api POST endpoint
    -> AgentGovernance (policy mutation, when applicable)
    -> Response (privileged action)
      -> Database (response state)
      -> Logs (audit event)
```

## Enforcement

- `Dashboard/` contains GET routes only.
- Firewall commands, Defender scans, and `Process.Kill` exist only in `Response/`.
- Raw telemetry models do not contain risk scores.
- A coalesced raw snapshot is the unit of collection and database persistence.
- Detection receives immutable observations and returns assessed DTOs.
- All assessed DTOs and alerts project one unified detection result.
- ATT&CK catalog coverage is separate from evidence-backed rule mappings.
- Mapped findings retain host and first/last-seen timestamps for dashboard review.
- AgentGovernance changes trust policy but does not perform privileged actions.
- SQLite persistence is isolated behind repository interfaces in `Database/`.
- Domain mutations and their audit records share one database transaction.
- Legacy JSON files are read only by the one-time compatibility importer.
- ThreatIntel normalizes local and external IOC observations behind provider
  adapters; credentials remain in deployment configuration.

## Compatibility

The existing browser API paths and JSON response shapes are preserved. Static assets moved from `wwwroot/` to `public/`; ASP.NET is configured with `WebRootPath = "public"`.

## Test Baseline

`tests/RoamSentinel.Tests` currently verifies:

- Unauthorized networked AI-agent risk scoring.
- Script-based persistence scoring.
- Private-address connection handling.
- Agent authorization state transitions.
- Blocking removes prior authorization.
- Safe configuration defaults and loopback binding validation.
- Migration completeness and idempotency.
- Transactional audit creation for repository writes.

Future test layers should add Windows adapter integration tests, endpoint
contract tests, and response-action dry-run tests.
