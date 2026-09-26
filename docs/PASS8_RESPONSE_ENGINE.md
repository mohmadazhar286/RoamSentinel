# PASS 8 - Controlled Response Engine

## Authorization

All response commands require:

1. A request originating from a loopback address.
2. An authenticated Analyst or Administrator session, depending on action.
3. A valid per-session CSRF token.
4. A configured `AccessControl__AdministratorToken` or fallback
   `Response__OperatorToken` environment variable.

The application fails closed when no login token is configured. Login secrets
are submitted once and are not stored by the browser. The session identifier is
held in an HttpOnly SameSite cookie; only the CSRF token is retained in browser
`sessionStorage`.

Generate and store a per-user token in PowerShell:

```powershell
.\scripts\Initialize-ResponseAuthorization.ps1
```

The script stores the token in the current user's environment and places it on
the clipboard without writing it to the repository. Restart RoamSentinel,
paste the token into **Response authorization**, then use the control plane. A
wrong, missing, remote, wrong-role, or invalid-CSRF attempt is logged.

## Actions

- Process termination records process identity and exit state.
- IP block/unblock uses paired Windows Firewall rules.
- Quick/full scans launch Microsoft Defender without blocking the dashboard.
- File response permits only regular files under the current user profile or
  temporary directory. Defender performs a custom scan and remediation; the UI
  does not claim quarantine when the file remains present.
- Startup disable supports standard HKCU/HKLM Run entries, startup-folder
  files, and explicitly addressed non-Microsoft scheduled tasks.
- Alert resolution and false-positive decisions preserve the event and review
  note.

## Evidence

Every attempt is stored in `response_actions`, including status, output,
error, actor, and JSON before/after snapshots. Successful startup changes also
write recovery metadata to `disabled_startup_items`. Every database write
creates an `audit_log` entry.
