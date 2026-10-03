using System.Text.Json;
using RoamSentinel.Core;

namespace RoamSentinel.App.DevOps;

public sealed class DevHubStatusService : IDevHubStatusService
{
    private static readonly string DevRoot = @"C:\dev";
    private static readonly string HubConfPath = Path.Combine(DevRoot, "registry", "hub.json");
    private static readonly string AppsConfPath = Path.Combine(DevRoot, "registry", "apps.json");
    private static readonly string PushStatusPath = Path.Combine(DevRoot, "sync", "logs", "last-push-status.json");
    private static readonly string PullLogsDir = Path.Combine(DevRoot, "sync", "logs");
    private static readonly string ClaimsDir = Path.Combine(DevRoot, "ledger", "claims");
    private static readonly string CyclesDir = Path.Combine(DevRoot, "ledger", "cycles");
    private static readonly string ReportsDir = Path.Combine(DevRoot, "reports", "daily");

    public Task<DevHubSummaryDto> GetSummaryAsync(CancellationToken cancellationToken = default)
    {
        var nodeInfo = LoadNodeInfo();
        var syncStatus = LoadSyncStatus();
        var activeClaims = LoadActiveClaims();
        var cycles = LoadCycles();
        var recentReports = LoadRecentReports();

        var summary = new DevHubSummaryDto(
            DateTimeOffset.UtcNow,
            nodeInfo,
            syncStatus,
            activeClaims,
            cycles,
            recentReports);

        return Task.FromResult(summary);
    }

    public Task<ActionResultDto> TriggerSyncAsync(string action, CancellationToken cancellationToken = default)
    {
        try
        {
            var isPush = string.Equals(action, "push", StringComparison.OrdinalIgnoreCase);
            var isPull = string.Equals(action, "pull", StringComparison.OrdinalIgnoreCase);

            if (!isPush && !isPull)
            {
                return Task.FromResult(new ActionResultDto(false, "", "Invalid sync action. Supported: push, pull."));
            }

            var scriptName = isPush ? "run-push-devsync.cmd" : "Pull-DevSync.ps1";
            var scriptPath = Path.Combine(DevRoot, "sync", scriptName);

            if (!File.Exists(scriptPath))
            {
                return Task.FromResult(new ActionResultDto(false, "", $"Sync script not found at {scriptPath}"));
            }

            var startInfo = isPush
                ? new System.Diagnostics.ProcessStartInfo("cmd.exe", $"/c \"{scriptPath}\"")
                : new System.Diagnostics.ProcessStartInfo("powershell.exe", $"-NoProfile -ExecutionPolicy Bypass -File \"{scriptPath}\"");

            startInfo.CreateNoWindow = true;
            startInfo.UseShellExecute = false;
            startInfo.WorkingDirectory = Path.Combine(DevRoot, "sync");

            using var process = System.Diagnostics.Process.Start(startInfo);
            return Task.FromResult(new ActionResultDto(
                true,
                $"Triggered {action} sync in background (PID {process?.Id ?? 0})",
                ""));
        }
        catch (Exception ex)
        {
            return Task.FromResult(new ActionResultDto(false, "", ex.Message));
        }
    }

    private static DevHubNodeInfoDto LoadNodeInfo()
    {
        try
        {
            if (File.Exists(HubConfPath))
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(HubConfPath));
                var root = doc.RootElement;
                return new DevHubNodeInfoDto(
                    root.TryGetProperty("node_id", out var nid) ? nid.GetString() ?? "pc-am" : "pc-am",
                    root.TryGetProperty("role", out var r) ? r.GetString() ?? "secondary-dev" : "secondary-dev",
                    root.TryGetProperty("owner", out var o) ? o.GetString() ?? "Operator" : "Operator",
                    root.TryGetProperty("tz_offset", out var tz) ? tz.GetString() ?? "+05:30" : "+05:30");
            }
        }
        catch
        {
            // Fallback
        }

        return new DevHubNodeInfoDto("pc-am", "secondary-dev", "Mohmad Azhar", "+05:30");
    }

    private static DevHubSyncStatusDto LoadSyncStatus()
    {
        DateTimeOffset? lastPushAt = null;
        var pushHealthy = true;
        var pushResults = new List<DevHubSyncRepoResultDto>();
        DateTimeOffset? lastPullAt = null;
        var pullHealthy = true;
        var totalManaged = 1;

        try
        {
            if (File.Exists(AppsConfPath))
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(AppsConfPath));
                if (doc.RootElement.TryGetProperty("apps", out var apps))
                {
                    totalManaged = apps.EnumerateObject().Count();
                }
            }
        }
        catch
        {
            // Ignore
        }

        try
        {
            if (File.Exists(PushStatusPath))
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(PushStatusPath));
                var root = doc.RootElement;
                if (root.TryGetProperty("timestamp", out var ts) &&
                    DateTimeOffset.TryParse(ts.GetString(), out var parsedTs))
                {
                    lastPushAt = parsedTs;
                }

                if (root.TryGetProperty("results", out var resArr))
                {
                    foreach (var item in resArr.EnumerateArray())
                    {
                        var name = item.TryGetProperty("name", out var n) ? n.GetString() ?? "unknown" : "unknown";
                        var status = item.TryGetProperty("status", out var s) ? s.GetString() ?? "" : "";
                        var msg = item.TryGetProperty("message", out var m) ? m.GetString() : null;
                        int? exit = item.TryGetProperty("exitCode", out var e) ? e.GetInt32() : null;

                        if (status.Contains("error", StringComparison.OrdinalIgnoreCase))
                        {
                            pushHealthy = false;
                        }

                        pushResults.Add(new DevHubSyncRepoResultDto(name, status, msg, exit));
                    }
                }
            }
        }
        catch
        {
            pushHealthy = false;
        }

        try
        {
            if (Directory.Exists(PullLogsDir))
            {
                var latestPullLog = Directory.GetFiles(PullLogsDir, "pull-*.log")
                    .Select(f => new FileInfo(f))
                    .OrderByDescending(f => f.LastWriteTimeUtc)
                    .FirstOrDefault();

                if (latestPullLog != null)
                {
                    lastPullAt = latestPullLog.LastWriteTimeUtc;
                }
            }
        }
        catch
        {
            // Ignore
        }

        return new DevHubSyncStatusDto(
            lastPushAt,
            pushHealthy,
            pushResults,
            lastPullAt,
            pullHealthy,
            totalManaged);
    }

    private static IReadOnlyList<DevHubClaimDto> LoadActiveClaims()
    {
        var claims = new List<DevHubClaimDto>();
        try
        {
            if (Directory.Exists(ClaimsDir))
            {
                foreach (var file in Directory.GetFiles(ClaimsDir, "*.json", SearchOption.AllDirectories))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(File.ReadAllText(file));
                        var root = doc.RootElement;
                        var status = root.TryGetProperty("status", out var st) ? st.GetString() ?? "" : "";

                        if (status is "active" or "ready")
                        {
                            var id = root.TryGetProperty("id", out var idProp) ? idProp.GetString() ?? "" : "";
                            var app = root.TryGetProperty("app", out var appProp) ? appProp.GetString() ?? "" : "";
                            var agent = root.TryGetProperty("agent", out var agProp) ? agProp.GetString() ?? "" : "";
                            var task = root.TryGetProperty("task", out var tProp) ? tProp.GetString() ?? "" : "";
                            var branch = root.TryGetProperty("branch", out var bProp) ? bProp.GetString() ?? "" : "";
                            var baseBranch = root.TryGetProperty("base", out var baseProp) ? baseProp.GetString() ?? "main" : "main";
                            var worktree = root.TryGetProperty("worktree", out var wtProp) ? wtProp.GetString() ?? "" : "";
                            var created = root.TryGetProperty("created", out var crProp) && DateTimeOffset.TryParse(crProp.GetString(), out var cDate)
                                ? cDate
                                : DateTimeOffset.UtcNow;
                            var lease = root.TryGetProperty("lease_until", out var lProp) && DateTimeOffset.TryParse(lProp.GetString(), out var lDate)
                                ? lDate
                                : DateTimeOffset.UtcNow.AddHours(8);
                            var cycle = root.TryGetProperty("cycle", out var cyProp) ? cyProp.GetString() : null;
                            var notes = root.TryGetProperty("notes", out var noProp) ? noProp.GetString() : null;

                            var scopes = new List<string>();
                            if (root.TryGetProperty("scope", out var scArr))
                            {
                                foreach (var sc in scArr.EnumerateArray())
                                {
                                    if (sc.GetString() is { } s) scopes.Add(s);
                                }
                            }

                            claims.Add(new DevHubClaimDto(
                                id,
                                app,
                                agent,
                                task,
                                scopes,
                                status,
                                branch,
                                baseBranch,
                                worktree,
                                created,
                                lease,
                                cycle,
                                notes));
                        }
                    }
                    catch
                    {
                        // Ignore individual corrupt claims
                    }
                }
            }
        }
        catch
        {
            // Ignore directory access error
        }

        return claims;
    }

    private static IReadOnlyList<DevHubCycleDto> LoadCycles()
    {
        var cycles = new List<DevHubCycleDto>();
        try
        {
            if (Directory.Exists(CyclesDir))
            {
                foreach (var file in Directory.GetFiles(CyclesDir, "*.json"))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(File.ReadAllText(file));
                        if (doc.RootElement.ValueKind == JsonValueKind.Array)
                        {
                            foreach (var item in doc.RootElement.EnumerateArray())
                            {
                                var id = item.TryGetProperty("id", out var idProp) ? idProp.GetString() ?? "" : "";
                                var name = item.TryGetProperty("name", out var nProp) ? nProp.GetString() ?? "" : "";
                                var start = item.TryGetProperty("start", out var sProp) && DateTimeOffset.TryParse(sProp.GetString(), out var sDate)
                                    ? sDate
                                    : DateTimeOffset.UtcNow;
                                var plannedEnd = item.TryGetProperty("planned_end", out var peProp) ? peProp.GetString() ?? "" : "";
                                var branch = item.TryGetProperty("branch", out var bProp) ? bProp.GetString() ?? "main" : "main";
                                var startVersion = item.TryGetProperty("start_version", out var svProp) ? svProp.GetString() ?? "0.9.0" : "0.9.0";
                                var closed = item.TryGetProperty("closed", out var cProp) && cProp.GetBoolean();

                                var goals = new List<string>();
                                if (item.TryGetProperty("goals", out var gArr))
                                {
                                    foreach (var g in gArr.EnumerateArray())
                                    {
                                        if (g.GetString() is { } goalStr) goals.Add(goalStr);
                                    }
                                }

                                cycles.Add(new DevHubCycleDto(
                                    id,
                                    name,
                                    goals,
                                    start,
                                    plannedEnd,
                                    branch,
                                    startVersion,
                                    closed));
                            }
                        }
                    }
                    catch
                    {
                        // Ignore
                    }
                }
            }
        }
        catch
        {
            // Ignore
        }

        return cycles;
    }

    private static IReadOnlyList<string> LoadRecentReports()
    {
        var reports = new List<string>();
        try
        {
            if (Directory.Exists(ReportsDir))
            {
                foreach (var dir in Directory.GetDirectories(ReportsDir)
                             .OrderByDescending(d => d)
                             .Take(5))
                {
                    reports.Add(Path.GetFileName(dir));
                }
            }
        }
        catch
        {
            // Ignore
        }

        return reports;
    }
}
