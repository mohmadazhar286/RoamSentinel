# Module Experience Architecture

RoamSentinel now exposes a module experience manifest so the console can render
module-wise workspaces without hardcoding all grouping decisions in browser
JavaScript.

Endpoint:

```text
GET /api/v1/module-experiences
```

The existing `/api/modules` endpoint remains unchanged and continues to expose
basic product module registration. The experience manifest is additive and is
intended for UI composition, future module-level packaging, and future
module-specific console shells.

## Boundary

The current runtime remains one Windows Service and one shared RS Console.
Isolation is contract-level:

- each module declares its workspace;
- each module declares its views;
- each module declares read and write API surfaces;
- the console builds workspace navigation from the manifest;
- module writes still use the existing authentication, authorization, CSRF,
  validation, logging, and audit controls.

The current isolation status is:

```text
single-runtime-isolated-contract
```

That means the module is not yet a separately deployable binary, but its UI
surface and API ownership are explicit enough to support future module-wise
experiences.

## Workspaces

- `protect`: device posture, integrity, malware, process, connection, app, and
  finding review.
- `codegate`: staged code, Git push, package, and deployment trust review.
- `devices`: mobile/companion and endpoint-device posture.
- `govern`: app/agent access, threat intelligence, insider-risk foundation, and
  audit.
- `respond`: operator-approved action history.
- `admin`: local configuration and policy.

## Scheduler surface

The protection scheduler is exposed as a first-class module experience instead
of a settings-only implementation detail.

```text
GET /api/v1/scheduler
```

The endpoint enriches scheduler task state with module ownership, workspace,
category, due state, health counts, and generated time. Existing scheduler
persistence remains behind the scheduler repository; the console only consumes
the read contract. The legacy `/api/dashboard/scheduler` endpoint remains
available for compatibility.

Current task ownership:

- `telemetry-snapshot`: `data-egress`
- `app-activity`: `app-activity`
- `malware-posture`: `malware-guard`
- `quick-scan`: `malware-guard`
- `full-scan`: `malware-guard`
- `weekly-review`: `protection-scheduler`

## Rule for future work

Do not add a new major console view without assigning it to a module experience.
Do not make a module view call another module's write API directly; route
cross-module effects through existing contracts and audited response flows.
