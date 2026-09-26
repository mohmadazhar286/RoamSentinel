# MITRE ATT&CK Mapping

## Coverage Model

RoamSentinel separates ATT&CK catalog coverage from detection mappings:

- `mitre_techniques` records techniques the platform recognizes.
- `mitre_mappings` links a detection rule to a technique.
- `detection_findings` retains mapped events with host and time.

This avoids assigning techniques to rules that do not have supporting
telemetry. A cataloged technique can therefore have zero events until a
specific detector is implemented.

## Common Technique Catalog

| Technique | Name | Primary tactic | Coverage |
|---|---|---|---|
| T1059 | Command and Scripting Interpreter | Execution | Parent mapping |
| T1547 | Boot or Logon Autostart Execution | Persistence | Parent mapping |
| T1053 | Scheduled Task/Job | Persistence | Parent mapping |
| T1003 | OS Credential Dumping | Credential Access | Cataloged |
| T1021 | Remote Services | Lateral Movement | Cataloged |
| T1105 | Ingress Tool Transfer | Command and Control | Cataloged |
| T1071 | Application Layer Protocol | Command and Control | Direct mapping |
| T1562 | Impair Defenses | Defense Evasion | Legacy alias |

Current sub-technique mappings remain available alongside parent techniques,
including T1059.001, T1547.001, and T1053.005.

MITRE replaced the former T1562 defense-impairment grouping in the current
catalog. RoamSentinel retains T1562 as a legacy alias for compatibility and
maps current Defender impairment to T1685. The catalog exposes
`status = Legacy` and `replaced_by = T1685` so the distinction is visible.

## Event Persistence

Mapped findings retain:

- Finding and rule identifiers
- Tactic and technique
- Mapping type
- Severity
- Host
- First seen and last seen timestamps
- Occurrence count
- Category, title, evidence, and entity identity

Unchanged finding sets are persisted at the configured detection interval.
Changed finding sets are written immediately. Each batch write is audited.
Purging reviewed logs also purges retained detection findings in the same
transaction.

## API

- `GET /api/mitre/techniques`
- `GET /api/mitre/events`

`/api/mitre/events` supports:

- `tactic`
- `technique`
- `severity`
- `host`
- `from`
- `to`
- `limit`

## Dashboard

The ATT&CK workspace shows:

- Mapped-event, tactic, technique, and host counts
- Tactic, technique, severity, and host filters
- Time-ordered mapped events
- Host and occurrence count
- Direct, parent, and legacy-alias mapping types
- Current and legacy technique catalog status

