# Security Model

## Security Objective

RoamSentinel protects a single Windows endpoint by improving visibility,
detection, review, and controlled response. It assumes the local Windows
account and operating system remain the primary trust anchors.

## Trust Boundaries

1. **Browser to local API:** restricted to loopback and authenticated sessions.
2. **API to Windows:** privileged changes pass through validated response
   methods and elevation checks.
3. **Application to SQLite:** repositories use parameterized SQL and controlled
   identifiers.
4. **Application to external intelligence:** provider adapters receive
   normalized indicators and externally supplied credentials.
5. **Application to AI agents:** executable paths and network behavior are
   observed; trust is explicit and reversible.
6. **Application directory to mutable state:** installed binaries are
   read-only; database, logs, and configuration are separated under
   `%ProgramData%\RoamSentinel`.

Local secrets use Windows DPAPI with `LocalMachine` scope and
application-specific entropy. Backup archives intentionally exclude secrets.
Restore requires an Administrator session plus CSRF validation (or explicit
local CLI invocation), validates product identity and SHA-256, and runs SQLite
`integrity_check` before replacing the database. A pre-restore safety copy is
retained.

## Authentication and Authorization

Roles are hierarchical:

| Role | Intended access |
|---|---|
| `Viewer` | Read dashboard and review state |
| `Analyst` | Viewer access plus enrichment and alert disposition |
| `Administrator` | Rules, settings, purge, agent policy, and response actions |

Tokens are configured outside source control. Successful login creates an
in-memory, short-lived session with an HttpOnly, SameSite `Strict` cookie.
Write requests require the session-specific CSRF token. Login, logout, denied
actions, and mutations are audited.

The server validates the bind URL as `localhost` or `127.0.0.1`. This is a
local administration surface, not a remote management console.

## Response Safety

- Every response request requires the appropriate role.
- Privileged actions also verify Windows elevation.
- User values are validated before reaching operating-system integrations.
- PowerShell script bodies are static; values are passed separately.
- Process invocation uses argument lists rather than concatenated shell text.
- Process termination protects essential Windows process names.
- File response is constrained to regular files in approved user-writable
  locations.
- Startup changes support known registry, startup-folder, and scheduled-task
  forms.
- Shared hosts such as `node.exe`, `python.exe`, and `code.exe` remain
  review-only for agent enforcement.
- Every attempt records success or failure and before/after evidence.

## Data Protection

- API responses use `no-store`.
- Browser responses include CSP, frame denial, MIME-sniff prevention,
  restricted permissions, and referrer controls.
- Dynamic UI content is escaped or assigned as text.
- API keys and access tokens must be environment variables or deployment
  secrets.
- SQLite and logs are local plaintext files protected by Windows filesystem
  permissions.
- Backup exports require an Administrator session and CSRF token, exclude
  configured secrets, and create an audit entry.
- Structured logs expire by configured age; reviewed security events require
  explicit purge.

For stronger at-rest protection, enable BitLocker and restrict the repository,
`data`, and `Logs` ACLs to the operating account and administrators.

## Detection and Agent Governance

Detection is evidence-based and weighted, not a guarantee of maliciousness.
Rules can be enabled or disabled and findings retain ATT&CK context. Threat
intelligence is enrichment; provider failure does not suppress other providers.

Agent status is `trusted`, `unknown`, or `blocked`. Trusting an executable path
does not grant blanket access to files or credentials; it only changes
RoamSentinel policy for that path. Actual file and network permissions remain
Windows responsibilities.

## Threats Addressed

- suspicious process and script execution
- persistence through startup entries and scheduled tasks
- unexpected network connections and suspicious indicators
- Defender or Firewall impairment
- unapproved or blocked AI agents
- unauthorized dashboard mutations
- command and SQL injection through exposed inputs
- unaudited response actions

## Limitations

- A local administrator can alter or delete the application, database, or logs.
- Exported archives contain endpoint security history and must be protected as
  sensitive data.
- RoamSentinel is not a kernel driver, packet-capture engine, sandbox, DLP
  product, or enterprise EDR.
- Encrypted traffic contents are not decrypted or inspected.
- Telemetry reflects Windows APIs and permissions available to the process.
- Protected directories may be skipped when Windows denies enumeration.
- In-memory sessions end when the application restarts.
- External provider accuracy, availability, quotas, and privacy policies remain
  outside RoamSentinel's control.

Use RoamSentinel with Defender, Windows Update, BitLocker, secure backups,
least-privilege accounts, and router/mobile-device security controls.

## Reporting Security Issues

Do not include tokens, API keys, personal paths, database files, or raw logs in
an issue report. Provide the affected version or commit, reproduction steps,
expected behavior, and sanitized evidence.
