# PASS 9 - AI Agent Governance

## Module Boundary

`AgentGovernance` identifies AI agents, evaluates trust and risk, and records
normalized observations. It does not execute firewall or process actions.
Enforcement remains in `Response`.

## Catalog

Migrations `2026070408` and `2026070409` seed and tune:

- ChatGPT Desktop
- Claude Desktop
- Cursor
- Windsurf
- Cline
- Roo Code
- Aider
- OpenHands
- VS Code Copilot
- Codex

Catalog matching uses agent name, executable path, and command line. The most
specific identity marker wins. Trusted-path markers are product-specific.

## Recorded State

Each executable instance records:

- canonical agent name and vendor
- executable path
- `trusted`, `unknown`, or `blocked` status
- first and last seen times
- running state and process ID
- connection and distinct public destination counts
- last network activity time
- risk score and reason
- explicit network authorization
- whether whole-executable enforcement is safe

Observations persist at a configurable interval. Activity rows are created only
for meaningful state, network, or risk changes.

## Risk Rules

- Known agent in a trusted path: low risk.
- Unknown or unapproved agent in user-writable, temporary, or download paths:
  high risk.
- Unknown agent elsewhere: medium risk.
- Blocked agent still running: critical.
- Unusual public destinations or nonstandard remote ports: high risk.

Shared hosts such as `node.exe`, `python.exe`, and `code.exe` are review-only
because blocking the host executable could affect unrelated applications.
