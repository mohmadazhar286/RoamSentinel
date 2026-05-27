# RoamSentinel

RoamSentinel is a local-first Windows endpoint defense dashboard for a PC that moves across networks. It runs as an ASP.NET Core app bound to `127.0.0.1:5117`.

## Run

```powershell
dotnet run --project C:\xampp\htdocs\PcGuardian
```

Open:

```text
http://127.0.0.1:5117
```

If the port is already in use:

```powershell
powershell -ExecutionPolicy Bypass -File C:\xampp\htdocs\PcGuardian\scripts\stop.ps1
```

Then start again:

```powershell
powershell -ExecutionPolicy Bypass -File C:\xampp\htdocs\PcGuardian\scripts\start.ps1
```

## Current Capabilities

- Posture view for triage rather than a Task Manager-style default screen
- Live TCP/UDP traffic inventory through Windows networking cmdlets
- Workload pressure view with total RAM, top memory consumers, top CPU consumers, private memory, threads, and handles
- Agent access control for Codex/Claude/Cursor/Windsurf-style tools by executable path
- Startup persistence checks for registry Run keys, startup folders, auto-start services, and scheduled tasks
- Microsoft Defender status
- Quick/full/deep Microsoft Defender scan trigger
- Windows Firewall IP block and restore actions
- Process stop action
- Persistent alert/action logs in `data\events.jsonl`
- Review views for logs, active rules, authorized agents, blocked agents, and RoamSentinel IP blocks
- Basic risk scoring for public connections, script-capable processes, user-writable paths, suspicious ports, stale scans, Defender state, and suspicious persistence locations

## Notes

- Firewall changes and stopping protected processes may require running the app as Administrator.
- This version binds only to localhost so it is not exposed to public Wi-Fi or other networks.
- Defender scans are launched in the background. A full scan can take a long time; the dashboard does not wait for it to finish.
- Deep scan updates Defender signatures first and then starts a full Defender scan.
- Agent blocking uses Windows Firewall outbound program rules. Authorizing an agent removes RoamSentinel's block rule for that executable path.
- Logs are retained until you purge them from the Review view.
- Scheduled-task persistence checks skip protected task folders that Windows will not allow RoamSentinel to read.
- The blocked-IP review lists IP firewall blocks RoamSentinel has stored in `data\ip-blocks.json`.
