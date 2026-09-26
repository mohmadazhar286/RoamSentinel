# RoamSentinel System Architecture Specification (RSAS v1.0)

## 1. Document Control

| Field | Value |
|---|---|
| Document | RoamSentinel System Architecture Specification |
| Identifier | RSAS |
| Version | 1.0 |
| Status | Architecture contract |
| Platform baseline | Windows-first |
| Applies to | RS Agent, RS Console, RS CodeGate, RS Control, RS Insider |
| Owners | RoamSentinel maintainers |
| Change control | Pull request with architecture review |

RSAS v1.0 is normative for new architecture work. Existing behavior that does
not yet satisfy this specification is transitional, not precedent. A deviation
requires a documented rationale, security impact, compatibility plan, and
approval by a maintainer responsible for the affected boundary.

The terms **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** express
requirement strength. Examples are illustrative unless explicitly marked
normative.

## 2. Purpose and Scope

This specification defines the system structure, trust boundaries, contracts,
data shapes, extension model, and engineering constraints for RoamSentinel. It
is intended to guide contributors implementing endpoint protection, code
inspection, organization management, insider-risk analysis, and integrations.

In scope:

- the Windows endpoint protection runtime;
- local Browser Console and RS Console clients;
- telemetry, event, policy, detection, response, and audit flows;
- RS CodeGate, RS Insider, and AI-agent governance boundaries;
- local persistence and future centralized control;
- sensors, threat feeds, plugins, and knowledge graph projections;
- security and non-functional requirements.

Out of scope for v1 implementation:

- a kernel-mode driver;
- packet decryption;
- general-purpose workflow automation;
- Linux, Android, router, cloud, or Kubernetes production support;
- a production multi-tenant RS Control service.

Those environments remain explicit extension points and must not distort the
Windows-first v1 contracts.

## 3. Product Vision

RoamSentinel is an explainable security platform composed of:

| Component | Responsibility |
|---|---|
| **RS Agent** | Continuous endpoint protection and local enforcement |
| **RS Console** | Local operator view using the shared console application |
| **RS CodeGate** | Pre-trust code, dependency, secret, and privacy analysis |
| **RS Control** | Future organization policy, fleet, and evidence plane |
| **RS Insider** | User and device behavior risk analysis |

The product converts observations into versioned events, evaluates those events
against policy and detection knowledge, records explainable decisions, and
executes authorized responses. It supplements operating-system controls; it
does not claim that every malicious action can be prevented.

## 4. Architectural Principles

1. Everything observable is represented as an event.
2. RS Agent, hosted as a Windows Service, is the protection engine.
3. Browser Console and RS Console are clients only.
4. UI components contain presentation and interaction logic, never security
   policy, detection, response, or persistence logic.
5. Modules communicate through explicit contracts and events.
6. A module never writes another module's storage directly.
7. Every mutation or response action is authenticated, authorized, validated,
   logged, audited, and CSRF-protected when initiated through a browser context.
8. Every detection, policy, and response decision is explainable from retained
   inputs, rule versions, and evidence.
9. Sensors and external intelligence providers are plugin-capable.
10. Public service APIs and serialized contracts are versioned.
11. Privileged operating-system calls remain inside the Response boundary.
12. Persistence remains behind Database repositories.
13. Security defaults fail closed; availability fallbacks must not grant
    authority.
14. Windows is the first-class v1 platform.
15. Compatibility is preserved through explicit adapters, not by leaking
    obsolete contracts into new modules.

## 5. High-Level Architecture

```text
+----------------------+       versioned HTTPS/loopback API
| Browser / RS Console | -----------------------------------+
+----------------------+                                    |
                                                            v
 +---------------------------------------------------------------+
 | RS Agent Windows Service                                      |
 |                                                               |
 |  API/Auth -> Commands -> Policy -> Response                    |
 |      |             |          |        |                      |
 |      v             v          v        v                      |
 |  Read Models    Event Bus -> Detection -> Findings            |
 |                    ^          |                                |
 |                    |          v                                |
 |  Sensors -> Telemetry       Knowledge Graph                   |
 |                    |          ^                                |
 |  Threat Feeds -----+----------+                                |
 |                    |                                           |
 |              Repositories -> SQLite / Audit / Logs             |
 +---------------------------------------------------------------+
             ^                    ^
             | contracts/events   | future mutually authenticated API
             |                    |
       +-----------+         +------------+
       | RS CodeGate|         | RS Control |
       +-----------+         +------------+
             |
       +-----------+
       | RS Insider |
       +-----------+
```

The in-process event bus is the v1 baseline. Contracts must permit a durable
broker implementation later without changing event semantics.

## 6. Deployment Models

### 6.1 Workstation

RS Agent runs automatically under a restricted service identity with only the
privileges required by enabled sensors and responses. RS Console is installed
for interactive local administration. Mutable state is under
`%ProgramData%\RoamSentinel`; per-user console state is under LocalAppData.

### 6.2 Windows Server VM

The same RS Agent binary and contracts apply. Server-specific policy disables
unsafe workstation assumptions. RS Console is optional on Desktop Experience
installations. Server Core uses the agent-only profile.

### 6.3 Future organization-managed deployment

```text
RS Control
    |
    | mutually authenticated, versioned management channel
    v
Site relay (optional)
    |
    +---- RS Agent A
    +---- RS Agent B
    +---- RS Agent C
```

Local protection must continue during control-plane loss. Remote policy is
signed, versioned, cached, and subject to local platform safety constraints.

### 6.4 Unsupported direct exposure

The v1 loopback API must not be directly exposed to a LAN or the Internet.
Remote management requires the future RS Control trust model.

## 7. Runtime Components

| Runtime component | Lifetime | Authority |
|---|---|---|
| RS Agent service host | Continuous | Service lifecycle and composition |
| API host | Agent lifetime | Versioned read and command endpoints |
| Telemetry collectors | Scheduled/event-driven | Observation only |
| Event dispatcher | Agent lifetime | Contract routing and backpressure |
| Policy engine | Agent lifetime | Policy evaluation, no OS mutation |
| Detection engine | Agent lifetime | Evidence-based findings |
| Response executor | On demand | Validated privileged operations |
| Repository layer | Agent lifetime | Domain-owned persistence |
| Structured logger | Agent lifetime | Operational/security records |
| RS Console | User session | API client only |
| Plugin host | Controlled | Capability-limited extension execution |

The composition root registers implementations. Modules must not locate
services through a global service provider.

## 8. Module Boundary Specification

| Module | Owns | Must not own |
|---|---|---|
| `Core` | Stable contracts, identifiers, envelopes | Infrastructure |
| `Telemetry` | Sensor scheduling and normalization | Risk or response |
| `Detection` | Rules, correlations, scores, findings | Collection or OS calls |
| `Response` | Privileged action validation/execution | UI or raw SQL |
| `ThreatIntel` | IOC normalization and feed adapters | Final block decisions |
| `AgentGovernance` | AI-agent identity, trust, activity risk | Direct enforcement |
| `DeviceShield` | Endpoint protection orchestration | Console rendering |
| `CodeGate` | Code intake and verdict pipeline | Endpoint telemetry ownership |
| `InsiderRisk` | User/device behavior analytics | Identity-provider mutation |
| `Dashboard` | Read-model contracts | Domain mutations |
| `Database` | Repositories, migrations, transactions | Policy decisions |
| `Logs` | Structured operational output | Domain source of truth |
| `Config` | Validated typed configuration | Mutable domain state |
| `app` | Composition, API security, orchestration | Module implementation logic |
| `Console` / `public` | Presentation and API interaction | Business logic |

Each persisted aggregate has one owning repository. Cross-module reads use a
query contract, projection, or event-derived view.

## 9. Inter-Module API Contracts

Contracts are immutable, nullable only where absence is meaningful, and carry a
schema version. New HTTP endpoints use `/api/v1/...`. Existing unversioned
endpoints are compatibility surfaces and should delegate to versioned
application services.

Command flow:

```text
Client request
  -> authentication
  -> role/capability authorization
  -> CSRF check (browser session)
  -> input/schema validation
  -> application command
  -> policy decision
  -> domain service
  -> repository transaction
  -> event + structured log + audit
  -> response DTO
```

Target C# contracts:

```csharp
public interface IEventPublisher
{
    ValueTask PublishAsync<TEvent>(
        EventEnvelope<TEvent> envelope,
        CancellationToken cancellationToken = default);
}

public interface IEventSubscriber<in TEvent>
{
    ValueTask HandleAsync(
        EventEnvelope<TEvent> envelope,
        CancellationToken cancellationToken = default);
}

public interface IDetectionEngine
{
    ValueTask<IReadOnlyList<DetectionDecision>> EvaluateAsync(
        IReadOnlyCollection<EventEnvelope> events,
        DetectionContext context,
        CancellationToken cancellationToken = default);
}

public interface IPolicyEngine
{
    ValueTask<PolicyDecision> EvaluateAsync(
        PolicyEvaluationRequest request,
        CancellationToken cancellationToken = default);
}

public interface IResponseExecutor
{
    ValueTask<ResponseExecutionResult> ExecuteAsync(
        AuthorizedResponseCommand command,
        CancellationToken cancellationToken = default);
}

public interface ITelemetrySink
{
    ValueTask WriteAsync(
        EventEnvelope telemetryEvent,
        CancellationToken cancellationToken = default);
}

public interface IPlugin
{
    PluginManifest Manifest { get; }
    ValueTask InitializeAsync(
        IPluginContext context,
        CancellationToken cancellationToken = default);
    ValueTask StopAsync(CancellationToken cancellationToken = default);
}

public interface IThreatFeed
{
    string FeedId { get; }
    IAsyncEnumerable<ThreatIndicator> ReadAsync(
        ThreatFeedCursor cursor,
        CancellationToken cancellationToken = default);
}
```

These are target interfaces. Migration from current interfaces must be
incremental and compatibility-tested.

## 10. Event Architecture

Events are append-oriented facts. Commands request change; events state what
was observed or completed. Events are never silently reinterpreted after
publication. Corrections produce new events referencing the superseded event.

Required envelope fields:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://schemas.roamsentinel.local/v1/event-envelope.schema.json",
  "type": "object",
  "required": [
    "eventId", "eventType", "schemaVersion", "occurredAt",
    "observedAt", "source", "hostId", "correlationId", "payload"
  ],
  "properties": {
    "eventId": { "type": "string", "format": "uuid" },
    "eventType": { "type": "string", "pattern": "^[a-z0-9]+(\\.[a-z0-9-]+)+$" },
    "schemaVersion": { "type": "integer", "minimum": 1 },
    "occurredAt": { "type": "string", "format": "date-time" },
    "observedAt": { "type": "string", "format": "date-time" },
    "source": { "type": "string" },
    "hostId": { "type": "string" },
    "actorId": { "type": ["string", "null"] },
    "correlationId": { "type": "string" },
    "causationId": { "type": ["string", "null"] },
    "classification": {
      "enum": ["public", "internal", "sensitive", "restricted"]
    },
    "payload": { "type": "object" }
  },
  "additionalProperties": false
}
```

Delivery is at least once. Subscribers must be idempotent using `eventId`.
Ordering is guaranteed only within a declared partition such as host/process.
Poison events are quarantined with validation errors and audit evidence.
Backpressure must drop or sample only telemetry classes explicitly configured
as lossy; audit and response events are never lossy.

## 11. Policy Engine

Policy is distinct from detection. Detection estimates security significance;
policy determines whether an operation is allowed, warned, denied, or requires
approval.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["ruleId", "version", "effect", "priority", "subject", "action"],
  "properties": {
    "ruleId": { "type": "string" },
    "version": { "type": "integer", "minimum": 1 },
    "enabled": { "type": "boolean", "default": true },
    "effect": { "enum": ["allow", "warn", "deny", "require-approval"] },
    "priority": { "type": "integer" },
    "subject": { "type": "object" },
    "action": { "type": "string" },
    "resource": { "type": "object" },
    "conditions": { "type": "array", "items": { "type": "object" } },
    "expiresAt": { "type": ["string", "null"], "format": "date-time" },
    "explanation": { "type": "string", "minLength": 1 }
  },
  "additionalProperties": false
}
```

Evaluation inputs include actor, role, device posture, requested action,
resource, source channel, time, and relevant risk. The deterministic result
contains the winning rule, considered rules, input hash, effect, explanation,
and engine version. Explicit deny wins at equal priority. Absence of an
applicable allow rule fails closed for privileged actions.

## 12. Telemetry Schema

Telemetry is normalized before publication. Raw provider data may be retained
as bounded evidence but cannot become the primary contract.

Process telemetry:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["processId", "name", "path", "startedAt", "user"],
  "properties": {
    "processId": { "type": "integer", "minimum": 0 },
    "parentProcessId": { "type": ["integer", "null"], "minimum": 0 },
    "name": { "type": "string" },
    "path": { "type": "string" },
    "commandLine": { "type": "string" },
    "user": { "type": "string" },
    "sessionId": { "type": ["integer", "null"] },
    "startedAt": { "type": "string", "format": "date-time" },
    "publisher": { "type": ["string", "null"] },
    "sha256": { "type": ["string", "null"], "pattern": "^[A-Fa-f0-9]{64}$" },
    "signatureStatus": { "enum": ["valid", "invalid", "unsigned", "unknown"] }
  },
  "additionalProperties": false
}
```

File telemetry:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["operation", "path", "processId", "timestamp"],
  "properties": {
    "operation": { "enum": ["create", "read", "write", "rename", "delete"] },
    "path": { "type": "string" },
    "previousPath": { "type": ["string", "null"] },
    "processId": { "type": "integer", "minimum": 0 },
    "user": { "type": ["string", "null"] },
    "size": { "type": ["integer", "null"], "minimum": 0 },
    "sha256": { "type": ["string", "null"], "pattern": "^[A-Fa-f0-9]{64}$" },
    "entropy": { "type": ["number", "null"], "minimum": 0, "maximum": 8 },
    "timestamp": { "type": "string", "format": "date-time" }
  },
  "additionalProperties": false
}
```

Network telemetry:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["protocol", "direction", "local", "remote", "processId"],
  "properties": {
    "protocol": { "enum": ["tcp", "udp", "icmp", "other"] },
    "direction": { "enum": ["inbound", "outbound", "unknown"] },
    "local": { "$ref": "#/$defs/endpoint" },
    "remote": { "$ref": "#/$defs/endpoint" },
    "processId": { "type": ["integer", "null"], "minimum": 0 },
    "state": { "type": ["string", "null"] },
    "bytesSent": { "type": ["integer", "null"], "minimum": 0 },
    "bytesReceived": { "type": ["integer", "null"], "minimum": 0 },
    "observedAt": { "type": "string", "format": "date-time" }
  },
  "$defs": {
    "endpoint": {
      "type": "object",
      "required": ["address", "port"],
      "properties": {
        "address": { "type": "string" },
        "port": { "type": "integer", "minimum": 0, "maximum": 65535 },
        "hostname": { "type": ["string", "null"] }
      },
      "additionalProperties": false
    }
  },
  "additionalProperties": false
}
```

All timestamps use UTC ISO 8601. Host-local display conversion belongs to the
client. Sensitive command lines and paths require classification and redaction.

## 13. Detection Engine

The engine consumes normalized events, policy context, threat intelligence, and
approved baselines. It emits immutable detection decisions and finding state
changes.

Each decision records:

- rule and rule-pack version;
- matched event IDs and extracted evidence;
- score components and confidence;
- severity mapping;
- ATT&CK or other knowledge mappings;
- suppressions and exceptions considered;
- human-readable explanation;
- engine version and evaluation time.

Detections must not execute responses directly. Correlation uses bounded
windows and explicit entity keys. Baselines are versioned inputs, not hidden
mutable state. Machine-learning output, when introduced, includes model
identity, features or feature summary, confidence, and deterministic safety
gates.

## 14. Response Engine

Response is the only module permitted to perform privileged Windows changes.
Every executor validates the command again at the privilege boundary.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": [
    "actionId", "actionType", "target", "requestedBy",
    "requestedAt", "authorization", "status"
  ],
  "properties": {
    "actionId": { "type": "string", "format": "uuid" },
    "actionType": { "type": "string" },
    "target": { "type": "object" },
    "requestedBy": { "type": "string" },
    "requestedAt": { "type": "string", "format": "date-time" },
    "authorization": {
      "type": "object",
      "required": ["policyDecisionId", "role"],
      "properties": {
        "policyDecisionId": { "type": "string" },
        "role": { "type": "string" },
        "approvalId": { "type": ["string", "null"] }
      }
    },
    "dryRun": { "type": "boolean" },
    "status": {
      "enum": ["requested", "validated", "running", "completed", "failed", "denied"]
    },
    "before": { "type": ["object", "null"] },
    "after": { "type": ["object", "null"] },
    "error": { "type": ["string", "null"] }
  },
  "additionalProperties": false
}
```

Executors should be reversible where Windows supports reversal. Irreversible
actions require explicit labeling and stronger approval. Dry-run follows the
same validation and audit path but performs no OS mutation.

## 15. Plugin Architecture

Sensors, parsers, threat feeds, and selected analyzers are plugin-capable.
Response plugins are disabled by default and require a trusted signature plus
an explicit deployment policy.

```text
Plugin package
  -> manifest validation
  -> signature and publisher trust
  -> compatibility check
  -> capability policy
  -> isolated load context/process
  -> health registration
  -> bounded event/API access
```

Plugin manifest:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["id", "name", "version", "apiVersion", "entryPoint", "capabilities"],
  "properties": {
    "id": { "type": "string", "pattern": "^[a-z0-9][a-z0-9.-]+$" },
    "name": { "type": "string" },
    "version": { "type": "string" },
    "apiVersion": { "type": "string", "pattern": "^v[0-9]+$" },
    "entryPoint": { "type": "string" },
    "publisher": { "type": "string" },
    "minimumAgentVersion": { "type": "string" },
    "platforms": {
      "type": "array",
      "items": { "enum": ["windows-x64", "windows-arm64"] }
    },
    "capabilities": {
      "type": "array",
      "items": {
        "enum": [
          "telemetry.read", "event.publish", "threat-feed.read",
          "code.analyze", "response.propose", "response.execute"
        ]
      }
    },
    "configurationSchema": { "type": ["object", "null"] },
    "signature": { "type": "object" }
  },
  "additionalProperties": false
}
```

Plugins never receive unrestricted repository or service-provider access.
Resource quotas cover CPU, memory, event rate, execution time, and network use.

## 16. Storage Model

The v1 local store is SQLite. Structured operational logs remain files. DPAPI
protects local secrets; secrets are not stored in backup archives or events.

```text
%ProgramData%\RoamSentinel\
  data\
    roamsentinel.db
    backups\
    quarantine-metadata\
  logs\
    app.log
    security.log
    response.log
    error.log
  config\
    appsettings.json
    *.secret
```

Storage rules:

- only Database repositories issue SQL;
- migrations are append-only and ordered;
- domain state and its audit record share a transaction where feasible;
- foreign keys and integrity checks are enabled;
- telemetry has retention and volume policies;
- audit and response evidence have separate retention policy;
- backups use consistent snapshots, checksums, manifests, and restore
  validation;
- deletion is policy-driven and itself audited;
- schema changes include forward migration and recovery analysis.

Cross-module projections may denormalize data but identify the source event and
projection version.

## 17. Security Knowledge Graph

The knowledge graph relates events, entities, findings, policies, ATT&CK
knowledge, vulnerabilities, code artifacts, users, devices, and responses. It
is initially a relational projection; a graph database is not required.

```text
(User)-[STARTED]->(Process)-[CONNECTED_TO]->(RemoteEndpoint)
   |                  |
   |                  +-[WROTE]->(File)-[HAS_HASH]->(Indicator)
   |                                      |
   +-[USES]->(Device)                     +-[MATCHED]->(Detection)
                                              |
                                              +-[MAPS_TO]->(Technique)
                                              +-[TRIGGERED]->(Response)
```

Knowledge graph node:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["nodeId", "nodeType", "schemaVersion", "properties"],
  "properties": {
    "nodeId": { "type": "string" },
    "nodeType": {
      "enum": [
        "host", "user", "process", "file", "endpoint", "code-artifact",
        "indicator", "detection", "technique", "policy", "response"
      ]
    },
    "schemaVersion": { "type": "integer", "minimum": 1 },
    "validFrom": { "type": "string", "format": "date-time" },
    "validTo": { "type": ["string", "null"], "format": "date-time" },
    "properties": { "type": "object" },
    "sourceEventIds": {
      "type": "array",
      "items": { "type": "string", "format": "uuid" }
    }
  },
  "additionalProperties": false
}
```

Knowledge graph edge:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["edgeId", "edgeType", "fromNodeId", "toNodeId", "observedAt"],
  "properties": {
    "edgeId": { "type": "string" },
    "edgeType": { "type": "string" },
    "fromNodeId": { "type": "string" },
    "toNodeId": { "type": "string" },
    "observedAt": { "type": "string", "format": "date-time" },
    "expiresAt": { "type": ["string", "null"], "format": "date-time" },
    "confidence": { "type": "number", "minimum": 0, "maximum": 1 },
    "properties": { "type": "object" },
    "sourceEventIds": {
      "type": "array",
      "items": { "type": "string", "format": "uuid" }
    }
  },
  "additionalProperties": false
}
```

Every graph assertion remains traceable to source events. Inference edges are
distinguished from observed edges and carry algorithm/version metadata.

## 18. Threat Model

Primary assets:

- enforcement authority;
- local secrets and sessions;
- policy and rule integrity;
- telemetry, audit, and evidence;
- code submitted to RS CodeGate;
- user-risk data;
- plugin trust and update channels.

Threat actors include malware under a standard user, malicious local users,
local administrators, compromised plugins or feeds, remote attackers reaching
an exposed API, and supply-chain attackers.

| Threat | Required controls |
|---|---|
| Unauthorized command | Loopback binding, authentication, RBAC, CSRF |
| Command/SQL injection | Typed validation, static commands, parameters |
| Privilege escalation | Response boundary, least-privilege service identity |
| Event spoofing | Source identity, schema validation, plugin capability checks |
| Audit tampering | ACLs, append semantics, export/signing roadmap |
| Plugin compromise | Signing, isolation, capabilities, quotas, kill switch |
| Feed poisoning | Provider identity, confidence, corroboration, expiry |
| Console compromise | No business logic or stored authority in UI |
| Backup disclosure | Admin authorization, secure destination, no secrets |
| Local administrator | Documented residual risk; external forwarding roadmap |
| Denial of service | Backpressure, quotas, bounded queries, health monitoring |
| Privacy breach | Minimization, classification, redaction, retention |

STRIDE review is required for new trust boundaries. Privacy review is required
for new user, content, command-line, file, or network collection.

## 19. Authentication, Authorization, and Secrets

Local roles are Viewer, Analyst, and Administrator. Future RS Control uses
device identity and organization-scoped roles without weakening local checks.

Requirements:

- tokens and keys never enter source control;
- local secrets use DPAPI with scoped entropy;
- sessions are short-lived, HttpOnly, SameSite Strict, and non-exportable;
- state-changing browser requests include a session-bound CSRF token;
- APIs authorize each action, not only each route group;
- privileged commands include a policy-decision reference;
- secret values are never logged, audited, or included in events;
- key rotation and revocation do not require database rewriting;
- plugin secrets are scoped per plugin and capability.

Authentication proves identity; authorization and policy still decide action.

## 20. Auditability and Compliance

Audit records cover authentication, authorization denial, policy change,
configuration change, plugin lifecycle, backup/restore, response request and
outcome, rule changes, IOC changes, and evidence deletion.

An audit record includes actor, action, target, time, success, correlation ID,
source channel, policy decision, and sanitized before/after evidence. Clocks are
UTC and clock-health issues are visible. Audit queries are bounded.

Future compliance features include signed audit export, external forwarding,
legal-hold retention, privacy subject handling, and organization-specific
control mappings. RoamSentinel must not claim compliance certification solely
because it records evidence.

## 21. Desktop/Web Console Strategy

Browser Console and RS Console render the same public application and call the
same API endpoints. A mode indicator may alter presentation labels, never
authority or features.

```text
Browser Console ----+
                    +--> shared static assets --> versioned API --> services
RS Console ---------+
```

Rules:

- feature and route parity is mandatory;
- no UI-specific domain implementation;
- clients render server-provided explanations and validation errors;
- clients do not infer authorization from hidden controls;
- security headers apply to browser content;
- RS Console navigation is restricted to the loopback origin;
- accessibility, keyboard navigation, theme contrast, and responsive layout
  are tested;
- sensitive tokens are not persisted by console code without an approved
  protected-storage design.

## 22. CodeGate Architecture

RS CodeGate scans pushed, imported, or selected code before trust.

```text
Intake -> isolate -> identify languages/manifests -> analyzers
       -> normalize findings -> policy -> allow/warn/block verdict
       -> evidence report + event publication
```

Analyzers cover secrets, suspicious scripts, dependency vulnerabilities,
privacy/data exposure, dangerous build hooks, and provenance. Intake is treated
as hostile. Analysis runs without executing submitted code unless an isolated
sandbox is explicitly introduced.

Verdicts are explainable and include analyzer versions, findings, severity,
policy rule, exceptions, and artifact digest. An allow verdict means no
blocking condition was found under the active policy; it is not a guarantee of
safety.

## 23. Insider Risk Architecture

RS Insider consumes minimized user, login, device, file, network, and
administrative events. It develops versioned baselines and emits explainable
risk changes for unusual file access, unusual login, mass copy/download,
suspicious administrative activity, and user/device risk.

Controls:

- purpose limitation and data minimization;
- explicit retention and access policy;
- separation of security evidence from personnel conclusions;
- explainable scores and contributing observations;
- no autonomous punitive action;
- human review before material action;
- jurisdiction and institutional policy review before deployment.

Baseline drift, cold-start behavior, shared accounts, service accounts, and
accessibility workflows must be modeled to reduce harmful false positives.

## 24. AI-Agent Governance Architecture

AI-agent governance identifies agent software, provider/model metadata when
available, executable path, plugins/tools, network behavior, workspace scope,
and declared capabilities.

Trust is explicit, scoped, reversible, and does not confer Windows access.
Shared runtime hosts are not blocked solely by process name. Enforcement
requires attributable executable or process evidence. Approval receipts link
actor, requested capability, scope, duration, policy, and resulting activity.

Agent events participate in Device Shield detections, RS Insider context, and
the knowledge graph without bypassing their module boundaries.

## 25. Extension Points

Supported target extension types:

- Windows telemetry sensors;
- event subscribers and projections;
- detection rule packs and correlation providers;
- threat-intelligence feeds;
- CodeGate analyzers;
- policy functions with deterministic output;
- response proposals and, under stronger trust, executors;
- knowledge mappings and export adapters;
- RS Control transport adapters.

Future platform adapters include Linux, Android, routers, cloud control planes,
and Kubernetes. Each adapter maps native observations to the common event
envelope while retaining platform-specific evidence in a namespaced payload.

## 26. Non-Functional Requirements

| Quality | Requirement |
|---|---|
| Availability | Local protection continues without UI or future RS Control |
| Startup | Agent reaches healthy state within 30 seconds on reference hardware |
| Resource use | Collectors are bounded and configurable; idle impact is measured |
| Latency | Critical event-to-decision target is under 5 seconds |
| Durability | Audit and response events are not intentionally dropped |
| Scalability | Contracts support one host now and fleet aggregation later |
| Security | Least privilege, fail closed, signed extension/update roadmap |
| Privacy | Minimize, classify, redact, retain, and delete by policy |
| Explainability | Decisions retain evidence, versions, score, and rationale |
| Maintainability | Module dependency direction is enforced by tests/review |
| Compatibility | Versioned additive changes; explicit deprecation windows |
| Accessibility | Console targets WCAG 2.2 AA contrast and keyboard operation |
| Recoverability | Validated backup/restore and documented rollback |
| Observability | Health, lag, drops, failures, and plugin status are measurable |

Performance targets require a documented reference environment and repeatable
benchmark before they become release gates.

## 27. Coding Standards

- Use nullable reference types and treat warnings as engineering defects.
- Prefer immutable records for contracts and explicit result types for expected
  failure.
- Async APIs accept `CancellationToken`; do not block asynchronous work.
- Validate at external boundaries and again at privilege boundaries.
- Never concatenate untrusted data into SQL, shell, PowerShell, paths, or URLs.
- Keep privileged Windows calls in `Response`.
- Keep persistence in Database repositories.
- Do not edit released migrations; append a new migration.
- Do not log secrets, raw tokens, or unnecessary personal data.
- Public contracts require versioning and compatibility tests.
- New events require schema, classification, retention, and ownership.
- New modules declare dependencies, events consumed/emitted, storage owner,
  threat model, and tests.
- UI changes must preserve Browser Console/RS Console parity.
- Contributions include rationale, tests, documentation, and rollback notes.

Architecture-affecting changes update RSAS or record why no RSAS change is
required.

## 28. Testing Strategy

Required layers:

1. unit tests for policy, detection, normalization, validation, and scoring;
2. contract tests for events, APIs, plugins, and backward compatibility;
3. repository and migration tests against SQLite;
4. ASP.NET test-host endpoint authentication/authorization/CSRF tests;
5. dry-run response tests with no OS mutation;
6. disposable Windows integration tests for privileged operations;
7. Browser Console/RS Console route and feature parity tests;
8. theme, accessibility, and security-header tests;
9. plugin isolation, signature, quota, and failure tests;
10. backup/restore, upgrade/rollback, soak, and fault-injection tests.

Security regressions block release. A test that requires elevation must identify
itself and run only in an isolated Windows test environment.

## 29. Roadmap Alignment

RSAS v1.0 is the architecture contract for roadmap work.

| Roadmap area | RSAS boundary |
|---|---|
| Reliable local agent | Sections 6, 7, 14, 16, 19 |
| ETW/Sysmon sensors | Sections 10, 12, 15 |
| Sigma/YARA/rule packs | Sections 13, 15 |
| Device Shield | Sections 7, 8, 13, 14 |
| RS CodeGate | Section 22 |
| RS Insider | Section 23 |
| AI-agent governance | Section 24 |
| RS Control/fleet | Sections 6, 9, 25 |
| Knowledge graph | Section 17 |
| Cloud/Kubernetes/platforms | Section 25 |
| Product readiness | Sections 18-20, 26-28 |

Near-term implementation should version HTTP APIs, establish the event
envelope and dispatcher, define module-owned event schemas, and preserve
compatibility adapters. Plugin loading, durable event transport, RS Control,
graph infrastructure, CodeGate analyzers, and Insider Risk analytics follow as
separately threat-modeled milestones.

## 30. Open Questions

1. Which event store and retention tiers are required beyond local SQLite?
2. Should plugins run in collectible load contexts, isolated worker processes,
   or both according to capability?
3. What signing authority and revocation mechanism governs plugins and rules?
4. Which service identity and Windows privileges are the minimum viable set?
5. How will RS Control establish device identity, tenancy, and policy signing?
6. Which event fields require field-level encryption or irreversible hashing?
7. What institutional privacy governance applies to RS Insider?
8. Which sandbox technology is acceptable for future dynamic CodeGate analysis?
9. How are knowledge graph inference confidence and expiry standardized?
10. What are the reference hardware and telemetry-volume performance baselines?
11. Which APIs remain local-only when RS Control is introduced?
12. What deprecation period applies to current unversioned API endpoints?

Open questions must be resolved through architecture decision records before
their answers become implementation dependencies.
