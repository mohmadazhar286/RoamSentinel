# PASS 11 - Logging and Auditability

## Structured Logs

RoamSentinel writes newline-delimited JSON records to:

- `Logs/app.log` - startup and completed API write requests
- `Logs/security.log` - authentication, rejected requests, alerts, policy and
  settings changes
- `Logs/response.log` - completed, failed, and denied response actions
- `Logs/error.log` - unhandled exceptions and shell-wrapper failures

Each record contains an UTC timestamp, level, event name, message, machine,
process ID, structured data, and exception metadata when applicable.

Files are created at startup. Expired structured logs are removed according to
`StructuredLogging:RetentionDays`.

## Audit Actions

The SQLite `audit_log` records:

- `authentication.login` and `authentication.logout`
- `settings.changed`
- `detection_rule.enabled_changed`
- `agent.trusted`, `agent.blocked`, and `agent.unblocked`
- `response.process.kill`
- `response.firewall.block_ip` and `response.firewall.unblock_ip`
- `response.defender.scan`
- `response.alert.resolved` and `response.alert.false_positive`

Response records also retain before/after JSON evidence in
`response_actions`.
