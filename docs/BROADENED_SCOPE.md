# RoamSentinel Broadened Scope

This document sets the direction for RoamSentinel beyond the current
single-endpoint dashboard. It does not weaken the existing security model: the
current RS Agent API remains loopback-only, and remote or multi-user operation
requires explicit new components and contracts.

## Product Direction

RoamSentinel becomes a Windows-first, offline-capable security and traceability
platform for local machines, university VMs, code intake points, and eventually
managed organizational environments.

The broadened product is split into five components:

| Component | Purpose |
|---|---|
| **RS Agent** | Protects and observes a Windows endpoint or server VM. |
| **RS Console** | Shows the local dashboard for an authorized operator. |
| **RS CodeGate** | Scans pushed, imported, cloned, downloaded, or packaged code before trust. |
| **RS Control** | Future organization management plane for fleet policy and evidence. |
| **RS Insider** | Future user/device behavior risk engine. |

## Target Use Cases

### 1. Local workstation protection

The current baseline remains the first-class use case. RS Agent monitors device
integrity, Defender posture, process and network behavior, startup persistence,
services, scheduled tasks, firewall state, installed software, and local audit
history.

### 2. Offline university VM security appliance

A university VM can run RS Agent and RS CodeGate after initial setup. Once the
VM is disconnected from the internet, RoamSentinel must continue to operate
from local rule packs, local advisory caches, local Defender signatures, and
local audit storage.

The VM deployment is intended for:

- security review of code pushed by multiple contributors;
- traceability of repository changes;
- logging of user, repository, branch, commit, file, and verdict evidence;
- local audit export for supervisors, administrators, or project records;
- offline operation after configuration is finalized.

### 3. Code intake and repository protection

RS CodeGate should become the security boundary for code before trust. It must
support these intake paths:

- `git push` through server-side hooks;
- `git clone` and `git pull` into monitored workspaces;
- ZIP/archive import;
- USB import;
- package install or dependency restore;
- manual local scan of a folder or repository.

For each intake event, CodeGate records a verdict:

- `allow`;
- `warn`;
- `block`;
- `needs_review`.

Verdicts must be explainable from retained evidence and policy versions.

### 4. Organization control

RS Control is a future component, not a reason to expose the current loopback
dashboard. It should provide:

- enrolled device inventory;
- signed policy distribution;
- audit export and report aggregation;
- fleet health;
- multi-operator RBAC;
- secure agent pairing;
- controlled evidence synchronization.

The current local API must not be reverse-proxied to act as RS Control.

### 5. Insider and user-risk analysis

RS Insider should be developed only after Device Integrity and CodeGate have
stable events. It should focus on explainable behavior patterns, not hidden
surveillance.

Candidate event families:

- unusual login;
- privilege escalation;
- mass file access;
- unusual repository activity;
- USB import/copy;
- suspicious admin activity;
- user/device risk score.

## Offline-First Requirements

Offline VM operation is a first-class broadened-scope requirement.

RoamSentinel must not require internet access at scan time for core security
decisions. Online enrichment is optional and must fail closed or degrade to
local evidence without suppressing local findings.

Offline-capable inputs:

- signed CodeGate rule bundles;
- hash-validated dependency advisory caches;
- local secret-detection patterns;
- local allowlists and suppressions;
- Defender signatures already present on the machine;
- manually imported IOC bundles.

Every imported bundle must include:

- product/component name;
- schema version;
- generated timestamp;
- source;
- SHA-256;
- optional signature metadata;
- import audit record.

The console should show freshness:

```text
CodeGate rules last updated: YYYY-MM-DD
Advisory cache last updated: YYYY-MM-DD
Defender signatures last updated: YYYY-MM-DD
IOC bundle last updated: YYYY-MM-DD
```

## CodeGate Evidence Model

Minimum evidence for each pushed or imported code event:

| Field | Requirement |
|---|---|
| Actor | Windows user, Git identity, or declared submitter. |
| Source | Git push, clone, pull, ZIP, USB, package install, or manual scan. |
| Repository/workspace | Local path and repository identifier when available. |
| Commit/branch | Commit hash and branch for Git events. |
| Files | Changed file paths, sizes, hashes, and categories. |
| Findings | Rule ID, severity, evidence, redacted sample, and explanation. |
| Verdict | `allow`, `warn`, `block`, or `needs_review`. |
| Policy | Policy version and rule bundle version. |
| Audit | Timestamp, host, operator, request ID, and immutable result ID. |

Secrets must be redacted. Store the secret type, file path, line number when
safe, and a keyed or truncated hash, not the raw secret.

## Security Boundaries

- RS Console remains a client.
- RS Agent remains the local protection engine.
- RS CodeGate owns code-intake decisions.
- RS Control owns future organization management.
- No UI component contains detection, response, or policy logic.
- No module writes another module's tables directly.
- Every write or response action remains authenticated, authorized, validated,
  logged, and audited.
- Browser-originated writes remain CSRF-protected.
- Offline mode must not bypass authentication or audit.

## Near-Term Build Order

1. **Device Integrity Findings v1**
   - Convert baseline changes into triageable findings.
   - Add approve/suppress/expected-change workflow.

2. **Offline CodeGate Foundation**
   - Add scan models, repository, migration, CLI, API, and dashboard table.
   - Add secret redaction tests and verdict tests.

3. **Git Hook Integration**
   - Add pre-receive/post-receive script templates.
   - Record actor, repository, branch, commit, files, verdict, and evidence.

4. **Offline Rule Bundle Import**
   - Add signed/hash-validated import for CodeGate rules and advisory caches.
   - Show freshness in RS Console.

5. **VM Deployment Profile**
   - Add documented offline VM setup.
   - Validate agent-only and CodeGate-enabled installation.

6. **RS Control Architecture Draft**
   - Define secure pairing, policy distribution, and evidence sync.
   - Do not implement by exposing the current loopback API.

## Non-Goals

Until explicitly implemented, RoamSentinel does not provide:

- complete enterprise EDR coverage;
- kernel-level malware prevention;
- decrypted traffic inspection;
- hidden employee surveillance;
- remote LAN access to the local dashboard;
- online vulnerability intelligence while the VM is offline;
- automatic deletion of pushed code or files without review policy.

