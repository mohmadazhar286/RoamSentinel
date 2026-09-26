# Testing RoamSentinel

## Prerequisites

- Windows 10 or later
- .NET 10 SDK
- PowerShell 7 or Windows PowerShell 5.1
- Node.js only for the optional dashboard JavaScript syntax check

Run commands from the RoamSentinel repository root.

## Restore and run

```powershell
dotnet restore .\RoamSentinel.slnx
dotnet test .\RoamSentinel.slnx --no-restore
```

For a clean verification:

```powershell
dotnet clean .\RoamSentinel.slnx
dotnet test .\RoamSentinel.slnx
```

## Focused suites

```powershell
dotnet test .\RoamSentinel.slnx --filter "FullyQualifiedName~DetectionEngineTests"
dotnet test .\RoamSentinel.slnx --filter "FullyQualifiedName~ThreatIntel"
dotnet test .\RoamSentinel.slnx --filter "FullyQualifiedName~AgentGovernanceServiceTests"
dotnet test .\RoamSentinel.slnx --filter "FullyQualifiedName~DatabaseMigrationTests"
dotnet test .\RoamSentinel.slnx --filter "Name~ResponseAction"
dotnet test .\RoamSentinel.slnx --filter "Name~Mitre"
```

List all discovered tests:

```powershell
dotnet test .\RoamSentinel.slnx --list-tests
```

## Coverage

The test project includes `coverlet.collector`.

```powershell
dotnet test .\RoamSentinel.slnx `
  --collect:"XPlat Code Coverage" `
  --results-directory .\TestResults
```

Coverage files are written under `TestResults\<run-id>\coverage.cobertura.xml`.

## Dashboard syntax check

```powershell
node --check .\public\app.js
```

## Test isolation

Automated tests use temporary SQLite databases and fake threat-intelligence
providers. They do not kill processes, change Windows Firewall rules, quarantine
files, or start Microsoft Defender scans. Temporary databases are removed after
each database test class run.

If the application is already listening on port `5117`, that does not normally
affect unit tests. To inspect the listener:

```powershell
Get-NetTCPConnection -LocalPort 5117 -State Listen |
  Select-Object LocalAddress, LocalPort, OwningProcess
```
