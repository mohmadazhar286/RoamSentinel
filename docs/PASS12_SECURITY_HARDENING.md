# PASS 12 - Security Hardening

## Authentication and Roles

The dashboard uses short-lived local sessions:

- `Viewer` - read-only dashboard access
- `Analyst` - threat-intelligence enrichment and alert disposition
- `Administrator` - response actions, rule changes, settings, purge, and AI
  agent policy changes

Configure tokens with environment variables:

- `AccessControl__ViewerToken`
- `AccessControl__AnalystToken`
- `AccessControl__AdministratorToken`

`Response__OperatorToken` remains an Administrator-token fallback for existing
installations.

Login secrets are submitted once. Session IDs use HttpOnly SameSite cookies.
Write requests require the session's `X-RoamSentinel-CSRF` token.

## Input and Execution Safety

- Controller input has explicit length, identifier, type, path, and range
  validation.
- SQL values use parameters. Dynamic SQL identifiers come only from internal
  fixed lists.
- PowerShell scripts are static trusted strings.
- User-controlled values are transported as validated environment parameters
  and passed directly to cmdlet parameters.
- `ProcessStartInfo.ArgumentList` is used instead of a shell command line.
- Parameter names, NUL characters, and oversized values are rejected.
- Response actions check both application role and Windows elevation.
- Shared AI-agent host processes remain review-only.

## Browser Hardening

Responses include CSP, frame denial, MIME sniffing prevention, no-referrer,
restricted browser permissions, and `no-store` caching for APIs. Dynamic values
are rendered through text assignment or HTML escaping.
