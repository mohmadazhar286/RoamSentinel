# Detection Engine

## Unified Evaluation

`DetectionEngine` evaluates one normalized `TelemetrySnapshot` against enabled
database rules. It emits one `DetectionResultDto` containing normalized
findings, target-level weighted scores, overall risk, and severity.

The existing process, network, startup, alert, and summary APIs are projections
of that result. They do not run separate detection logic.

## Rule Model

Rules are stored in `detection_rules` with:

- Rule ID and name
- Category and description
- Enabled state
- Severity
- Risk weight
- Confidence
- JSON configuration
- Created and updated timestamps

ATT&CK mappings are stored separately in `mitre_mappings`. Rule state changes
and their audit row commit in the same transaction.

Supported severities are `Info`, `Low`, `Medium`, `High`, and `Critical`.

## Weighted Scoring

Each matched rule contributes its configured `risk_weight` to the affected
entity. Multiple rule weights for one entity are summed and capped at 100.
Overall endpoint risk is the highest entity score in the snapshot.

Configured score bands:

- Info: below the low threshold
- Low: low threshold or above
- Medium: medium threshold or above
- High: high threshold or above
- Critical: critical threshold or above

Rule severity remains explicit metadata and is not inferred from its category.

## Seeded Rules

| Rule | Category | ATT&CK |
|---|---|---|
| PowerShell encoded command | Execution | T1059.001 |
| Executable launched from temporary directory | Execution | T1204.002 |
| Unknown executable with network activity | Network | T1071 |
| Suspicious startup persistence | Persistence | T1547.001 |
| Suspicious scheduled task persistence | Persistence | T1053.005 |
| AI agent executing from untrusted path | Agent Governance | T1204.002 |
| Process connected to suspicious IP | Threat Intelligence | T1071 |
| Microsoft Defender disabled | Defense Impairment | T1685 |
| Windows Firewall profile disabled | Defense Impairment | T1686.003 |

The mappings follow the current MITRE ATT&CK catalog:

- [PowerShell T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [Registry Run Keys / Startup Folder T1547.001](https://attack.mitre.org/techniques/T1547/001/)
- [Scheduled Task T1053.005](https://attack.mitre.org/techniques/T1053/005/)
- [Disable or Modify Tools T1685](https://attack.mitre.org/techniques/T1685/)
- [Windows Host Firewall T1686.003](https://attack.mitre.org/techniques/T1686/003/)

## API

- `GET /api/detections`: current unified result and findings.
- `GET /api/detection/rules`: rules, categories, descriptions, weights,
  enable state, and ATT&CK mappings.
- `POST /api/detection/rules/{ruleId}/enabled`: enable or disable one rule
  using `{ "enabled": true|false }`.

The POST route is registered in `app/Api`; Dashboard remains read-only.

## Detection Scope

The initial catalog detects:

- Encoded PowerShell arguments using captured process command lines.
- Executables running from Temp.
- Network-active processes whose executable path is unavailable, excluding
  known protected Windows components.
- Suspicious Run-key/startup-folder commands.
- Suspicious non-system scheduled tasks.
- Running AI agents outside the authorized-path policy.
- Connections matching active suspicious IP indicators.
- Disabled Defender antivirus or real-time protection.
- Disabled Windows Firewall profiles.

Unknown-path findings mean Windows did not expose the executable path. They do
not by themselves prove malware and should be reviewed with process identity,
publisher, and network evidence.

