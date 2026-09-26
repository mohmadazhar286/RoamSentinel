# Threat Intelligence

## Supported Indicators

The enrichment layer normalizes and validates:

- IP addresses: IPv4 and IPv6
- Domains
- File hashes: MD5, SHA-1, and SHA-256

Malformed values are rejected before any provider request.

## Resolution Order

1. Active local IOC record
2. Active cached provider observation
3. Enabled and configured external provider

Provider observations are normalized into reputation, confidence, summary,
reference, observation time, and expiry. The strongest reputation is returned
while all provider observations remain visible.

Local IOC and provider cache records use `threat_indicators`. Provider results
expire according to `ThreatIntel:CacheMinutes`. Local records can optionally
have an expiry and feed suspicious-IP detection immediately.

## Providers

| Provider | IP | Domain | File hash | Authentication |
|---|---:|---:|---:|---|
| VirusTotal API v3 | Yes | Yes | Yes | `x-apikey` |
| AbuseIPDB API v2 | Yes | No | No | `Key` |
| AlienVault OTX | Yes | Yes | Yes | `X-OTX-API-KEY` |
| MISP | Yes | Yes | Yes | `Authorization` |

Provider adapters are disabled by default and do not make network requests
without both `Enabled=true` and a non-empty API key.

## Credential Configuration

Do not put real credentials in `appsettings.json`. ASP.NET Core maps environment
variables with double underscores to nested configuration:

```powershell
$env:ThreatIntel__VirusTotal__Enabled = 'true'
$env:ThreatIntel__VirusTotal__ApiKey = '<secret>'

$env:ThreatIntel__AbuseIpDb__Enabled = 'true'
$env:ThreatIntel__AbuseIpDb__ApiKey = '<secret>'

$env:ThreatIntel__AlienVaultOtx__Enabled = 'true'
$env:ThreatIntel__AlienVaultOtx__ApiKey = '<secret>'

$env:ThreatIntel__Misp__Enabled = 'true'
$env:ThreatIntel__Misp__BaseUrl = 'https://misp.example.org'
$env:ThreatIntel__Misp__ApiKey = '<secret>'
```

MISP TLS verification defaults to enabled. Disable it only for a controlled
local instance with a certificate that cannot yet be trusted:

```powershell
$env:ThreatIntel__Misp__VerifyTls = 'false'
```

Provider status endpoints expose only enabled/configured booleans, never key
values.

## API

Read-only:

- `GET /api/threat-intel/providers`
- `GET /api/threat-intel/iocs`

Commands:

- `POST /api/threat-intel/enrich`
- `POST /api/threat-intel/local-iocs`
- `POST /api/threat-intel/local-iocs/remove`

Enrichment request:

```json
{
  "indicator": "example.org",
  "indicatorType": "domain"
}
```

Local IOC request:

```json
{
  "indicator": "203.0.113.10",
  "indicatorType": "ip",
  "reputation": "Malicious",
  "confidence": 95,
  "description": "Internal blocklist",
  "tags": ["local", "reviewed"],
  "expiresAt": null
}
```

Local IOC mutations and provider-cache writes are recorded in `audit_log`.

## Provider References

- [VirusTotal API v3](https://docs.virustotal.com/reference/overview)
- [AbuseIPDB API v2](https://docs.abuseipdb.com/)
- [MISP OpenAPI](https://www.misp-project.org/openapi/)
- [AlienVault OTX API](https://otx.alienvault.com/api)

