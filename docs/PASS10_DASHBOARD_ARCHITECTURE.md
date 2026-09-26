# PASS 10 - Dashboard Architecture

## Sections

The operator dashboard exposes ten sections:

1. Security Overview
2. Live Processes
3. Network Connections
4. Alerts
5. MITRE ATT&CK
6. AI Agent Governance
7. Threat Intel
8. Response History
9. Settings
10. Audit Log

## Read Boundary

The browser calls read-only controllers under `/api/dashboard/*`.
`DashboardSectionEndpoints` performs HTTP binding only and delegates to
`IDashboardQueryService`. `DashboardQueryService` composes presentation models
from telemetry, detection, governance, threat-intelligence, response, settings,
and audit services.

The dashboard does not:

- execute PowerShell
- kill processes
- change firewall rules
- scan or quarantine files
- modify agent policy directly
- issue SQL

Response controls continue to call authorized `/api/actions/*` controllers.
All validation and privileged behavior remains in the owning service modules.

## Compatibility

Earlier telemetry endpoints remain available for compatibility. Persistence
inventory and policy review are presented inside Settings, while process-load
telemetry is presented inside Live Processes.

Response History and Audit Log return the latest 200 records per view. The
database retains the complete configured history.
