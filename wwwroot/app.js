const state = {
  activeView: "alerts",
  refreshMs: 8000
};

const els = {
  adminState: document.querySelector("#adminState"),
  updatedAt: document.querySelector("#updatedAt"),
  connectionCount: document.querySelector("#connectionCount"),
  processCount: document.querySelector("#processCount"),
  memoryUsed: document.querySelector("#memoryUsed"),
  startupCount: document.querySelector("#startupCount"),
  alertCount: document.querySelector("#alertCount"),
  postureState: document.querySelector("#postureState"),
  highFindingCount: document.querySelector("#highFindingCount"),
  mediumFindingCount: document.querySelector("#mediumFindingCount"),
  defenderPosture: document.querySelector("#defenderPosture"),
  defenderService: document.querySelector("#defenderService"),
  defenderAv: document.querySelector("#defenderAv"),
  defenderRealtime: document.querySelector("#defenderRealtime"),
  defenderSignature: document.querySelector("#defenderSignature"),
  actionMessage: document.querySelector("#actionMessage"),
  alertsBody: document.querySelector("#alertsBody"),
  connectionsBody: document.querySelector("#connectionsBody"),
  processesBody: document.querySelector("#processesBody"),
  ramText: document.querySelector("#ramText"),
  ramBar: document.querySelector("#ramBar"),
  heavyMemoryCount: document.querySelector("#heavyMemoryCount"),
  heavyCpuCount: document.querySelector("#heavyCpuCount"),
  topMemoryBody: document.querySelector("#topMemoryBody"),
  topCpuBody: document.querySelector("#topCpuBody"),
  startupBody: document.querySelector("#startupBody"),
  agentsBody: document.querySelector("#agentsBody"),
  logsBody: document.querySelector("#logsBody"),
  policyRulesBody: document.querySelector("#policyRulesBody"),
  authorizedAgentsBody: document.querySelector("#authorizedAgentsBody"),
  blockedAgentsBody: document.querySelector("#blockedAgentsBody"),
  blockedIpsBody: document.querySelector("#blockedIpsBody")
};

document.querySelectorAll(".tab").forEach((button) => {
  button.addEventListener("click", () => switchView(button.dataset.view));
});
document.querySelectorAll("[data-jump-view]").forEach((button) => {
  button.addEventListener("click", () => switchView(button.dataset.jumpView));
});

document.querySelector("#quickScan").addEventListener("click", () => runScan("quick"));
document.querySelector("#fullScan").addEventListener("click", () => runScan("full"));
document.querySelector("#deepScan").addEventListener("click", () => runScan("deep"));
document.querySelector("#purgeLogs").addEventListener("click", purgeLogs);
document.querySelector("#reviewLogs").addEventListener("click", () => switchView("logs"));
document.querySelector("#enforceAgents").addEventListener("click", enforceAgents);
document.querySelector("#blockForm").addEventListener("submit", blockIp);

refreshAll();
setInterval(refreshAll, state.refreshMs);

function switchView(view) {
  state.activeView = view;
  document.querySelectorAll(".tab").forEach((tab) => tab.classList.toggle("active", tab.dataset.view === view));
  document.querySelectorAll(".view").forEach((panel) => panel.classList.toggle("active", panel.id === view));
  refreshView(view);
}

async function refreshAll() {
  try {
    const summary = await getJson("/api/summary");
    els.adminState.textContent = summary.isAdministrator ? "Admin mode" : "Standard mode";
    els.adminState.style.background = summary.isAdministrator ? "#edf8f1" : "#fff7e8";
    els.connectionCount.textContent = summary.connectionCount;
    els.processCount.textContent = summary.processCount;
    els.startupCount.textContent = summary.startupEntryCount;
    els.alertCount.textContent = summary.highAlerts + summary.mediumAlerts + summary.lowAlerts;
    els.highFindingCount.textContent = summary.highAlerts;
    els.mediumFindingCount.textContent = summary.mediumAlerts;
    els.postureState.textContent = summary.highAlerts > 0 ? "Attention" : summary.mediumAlerts > 0 ? "Review" : "Stable";
    els.postureState.className = summary.highAlerts > 0 ? "state-danger" : summary.mediumAlerts > 0 ? "state-warning" : "state-ok";
    els.updatedAt.textContent = `Updated ${formatTime(summary.generatedAt)}`;
    renderDefender(summary.defender);
    const performance = await getJson("/api/performance");
    renderPerformanceSummary(performance);
    if (state.activeView === "performance") {
      renderPerformance(performance);
    } else {
      refreshView(state.activeView);
    }
  } catch (error) {
    setMessage(error.message, true);
  }
}

async function refreshView(view) {
  if (view === "alerts") renderAlerts(await getJson("/api/alerts"));
  if (view === "performance") renderPerformance(await getJson("/api/performance"));
  if (view === "connections") renderConnections(await getJson("/api/connections"));
  if (view === "processes") renderProcesses(await getJson("/api/processes"));
  if (view === "startup") renderStartup(await getJson("/api/startup"));
  if (view === "agents") renderAgents(await getJson("/api/agents"));
  if (view === "logs") renderLogs(await getJson("/api/logs"));
  if (view === "policies") renderPolicies(await getJson("/api/policies"));
}

function renderDefender(defender) {
  els.defenderService.textContent = yesNo(defender.serviceEnabled);
  els.defenderAv.textContent = yesNo(defender.antivirusEnabled);
  els.defenderRealtime.textContent = yesNo(defender.realTimeProtectionEnabled);
  els.defenderSignature.textContent = defender.signatureVersion || "Unknown";
  els.defenderPosture.textContent = defender.antivirusEnabled && defender.realTimeProtectionEnabled ? "On" : "Needs review";
  els.defenderPosture.className = defender.antivirusEnabled && defender.realTimeProtectionEnabled ? "state-ok" : "state-danger";
}

function renderAlerts(alerts) {
  els.alertsBody.innerHTML = rowsOrEmpty(alerts, 5, (alert) => `
    <tr>
      <td><span class="risk ${severityClass(alert.severity)}">${escapeHtml(alert.severity)}</span></td>
      <td>${escapeHtml(alert.category)}</td>
      <td>${escapeHtml(alert.title)}</td>
      <td class="detail">${escapeHtml(alert.detail)}</td>
      <td>${formatTime(alert.timestamp)}</td>
    </tr>
  `);
}

function renderLogs(logs) {
  els.logsBody.innerHTML = rowsOrEmpty(logs, 5, (log) => `
    <tr>
      <td>${formatTime(log.timestamp)}</td>
      <td><span class="risk ${severityClass(log.severity)}">${escapeHtml(log.severity)}</span></td>
      <td>${escapeHtml(log.category)}</td>
      <td>${escapeHtml(log.title)}</td>
      <td class="detail">${escapeHtml(log.detail)}</td>
    </tr>
  `);
}

function renderConnections(connections) {
  els.connectionsBody.innerHTML = rowsOrEmpty(connections, 7, (connection) => `
    <tr>
      <td><span class="risk ${riskClass(connection.riskScore)}">${connection.riskScore}</span></td>
      <td>${escapeHtml(connection.processName)}</td>
      <td>${connection.processId}</td>
      <td>${escapeHtml(connection.protocol)}</td>
      <td>${escapeHtml(connection.remoteAddress || "-")}:${connection.remotePort || "-"}</td>
      <td>${escapeHtml(connection.state)}</td>
      <td class="detail">${escapeHtml(connection.riskReason || "")}</td>
    </tr>
  `);
}

function renderPerformanceSummary(performance) {
  els.memoryUsed.textContent = `${performance.memory.usedPercent}%`;
  els.ramText.textContent = `${performance.memory.usedGb} GB / ${performance.memory.totalGb} GB`;
  els.ramBar.style.width = `${Math.min(performance.memory.usedPercent, 100)}%`;
  els.ramBar.className = performance.memory.usedPercent >= 85 ? "danger" : performance.memory.usedPercent >= 70 ? "warning" : "";
  els.heavyMemoryCount.textContent = performance.heavyMemoryProcessCount;
  els.heavyCpuCount.textContent = performance.heavyCpuProcessCount;
}

function renderPerformance(performance) {
  renderPerformanceSummary(performance);
  els.topMemoryBody.innerHTML = rowsOrEmpty(performance.topMemoryProcesses || [], 6, (process) => `
    <tr>
      <td>${escapeHtml(process.name)}</td>
      <td>${process.processId}</td>
      <td>${formatMb(process.memoryMb)}</td>
      <td>${formatMb(process.privateMemoryMb)}</td>
      <td>${formatCpu(process.cpuPercent)}</td>
      <td><button class="mini-button" type="button" data-kill="${process.processId}" data-name="${escapeHtml(process.name)}">Stop</button></td>
    </tr>
  `);
  els.topCpuBody.innerHTML = rowsOrEmpty(performance.topCpuProcesses || [], 6, (process) => `
    <tr>
      <td>${escapeHtml(process.name)}</td>
      <td>${process.processId}</td>
      <td>${formatCpu(process.cpuPercent)}</td>
      <td>${formatMb(process.memoryMb)}</td>
      <td>${process.threadCount}</td>
      <td><button class="mini-button" type="button" data-kill="${process.processId}" data-name="${escapeHtml(process.name)}">Stop</button></td>
    </tr>
  `);
  bindKillButtons(els.topMemoryBody);
  bindKillButtons(els.topCpuBody);
}

function renderProcesses(processes) {
  els.processesBody.innerHTML = rowsOrEmpty(processes, 11, (process) => `
    <tr>
      <td><span class="risk ${riskClass(process.riskScore)}">${process.riskScore}</span></td>
      <td>${escapeHtml(process.name)}</td>
      <td>${process.processId}</td>
      <td>${formatCpu(process.cpuPercent)}</td>
      <td>${formatMb(process.memoryMb)}</td>
      <td>${formatMb(process.privateMemoryMb)}</td>
      <td>${process.threadCount}</td>
      <td>${process.handleCount}</td>
      <td>${process.connectionCount}</td>
      <td class="path">${escapeHtml(process.path || "")}</td>
      <td>
        <button class="mini-button" type="button" data-kill="${process.processId}" data-name="${escapeHtml(process.name)}">Stop</button>
      </td>
    </tr>
  `);

  bindKillButtons(els.processesBody);
}

function bindKillButtons(scope) {
  scope.querySelectorAll("[data-kill]").forEach((button) => {
    button.addEventListener("click", () => killProcess(Number(button.dataset.kill), button.dataset.name));
  });
}

function renderAgents(view) {
  const rows = view.runningAgents || [];
  els.agentsBody.innerHTML = rowsOrEmpty(rows, 6, (agent) => `
    <tr>
      <td><span class="risk ${agent.networkAuthorized ? "low" : "high"}">${agent.networkAuthorized ? "Allowed" : "Unapproved"}</span></td>
      <td>${escapeHtml(agent.name)}</td>
      <td>${agent.processId}</td>
      <td>${agent.connectionCount}</td>
      <td class="path">${escapeHtml(agent.path || "")}</td>
      <td class="button-row">
        <button class="mini-button allow" type="button" data-authorize="${escapeHtml(agent.path || "")}">Authorize</button>
        <button class="mini-button" type="button" data-block-agent="${escapeHtml(agent.path || "")}">Block</button>
      </td>
    </tr>
  `);

  els.agentsBody.querySelectorAll("[data-authorize]").forEach((button) => {
    button.addEventListener("click", () => updateAgentPolicy("/api/actions/authorize-agent", button.dataset.authorize, "authorize"));
  });
  els.agentsBody.querySelectorAll("[data-block-agent]").forEach((button) => {
    button.addEventListener("click", () => updateAgentPolicy("/api/actions/block-agent", button.dataset.blockAgent, "block"));
  });
}

function renderPolicies(review) {
  els.policyRulesBody.innerHTML = rowsOrEmpty(review.activePolicies || [], 2, (policy) => `
    <tr>
      <td>${escapeHtml(policy.name)}</td>
      <td class="detail">${escapeHtml(policy.detail)}</td>
    </tr>
  `);
  els.authorizedAgentsBody.innerHTML = rowsOrEmpty(review.authorizedAgentPaths || [], 1, (path) => `
    <tr><td class="path">${escapeHtml(path)}</td></tr>
  `);
  els.blockedAgentsBody.innerHTML = rowsOrEmpty(review.blockedAgentPaths || [], 2, (path) => `
    <tr>
      <td class="path">${escapeHtml(path)}</td>
      <td><button class="mini-button allow" type="button" data-unblock-agent="${escapeHtml(path)}">Restore</button></td>
    </tr>
  `);
  els.blockedIpsBody.innerHTML = rowsOrEmpty(review.blockedIps || [], 3, (block) => `
    <tr>
      <td>${escapeHtml(block.ipAddress)}</td>
      <td>${formatTime(block.blockedAt)}</td>
      <td><button class="mini-button allow" type="button" data-unblock-ip="${escapeHtml(block.ipAddress)}">Restore</button></td>
    </tr>
  `);

  els.blockedAgentsBody.querySelectorAll("[data-unblock-agent]").forEach((button) => {
    button.addEventListener("click", () => restoreAgent(button.dataset.unblockAgent));
  });
  els.blockedIpsBody.querySelectorAll("[data-unblock-ip]").forEach((button) => {
    button.addEventListener("click", () => restoreIp(button.dataset.unblockIp));
  });
}

function renderStartup(entries) {
  els.startupBody.innerHTML = rowsOrEmpty(entries, 4, (entry) => `
    <tr>
      <td><span class="risk ${riskClass(entry.riskScore)}">${entry.riskScore}</span></td>
      <td>${escapeHtml(entry.name)}</td>
      <td>${escapeHtml(entry.source)}</td>
      <td class="path">${escapeHtml(entry.command)}</td>
    </tr>
  `);
}

async function runScan(type) {
  const label = type === "deep" ? "Deep" : type === "full" ? "Full" : "Quick";
  setMessage(`${label} scan requested...`);
  const result = await postJson("/api/actions/scan", { type });
  setMessage(result.ok ? `${label} scan started in the background.` : result.error, !result.ok);
  refreshAll();
}

async function blockIp(event) {
  event.preventDefault();
  const ipAddress = new FormData(event.currentTarget).get("ip")?.toString().trim();
  if (!ipAddress) return setMessage("Enter an IP address to block.", true);
  if (!confirm(`Add Windows Firewall block rules for ${ipAddress}?`)) return;
  const result = await postJson("/api/actions/block-ip", { ipAddress });
  setMessage(result.ok ? `Firewall block requested for ${ipAddress}.` : result.error, !result.ok);
  refreshAll();
}

async function killProcess(processId, name) {
  if (!confirm(`Stop ${name} (${processId}) and its child processes?`)) return;
  const result = await postJson("/api/actions/kill-process", { processId });
  setMessage(result.ok ? result.output : result.error, !result.ok);
  refreshAll();
}

async function updateAgentPolicy(url, path, action) {
  if (!path) return setMessage("Agent path is unavailable.", true);
  const verb = action === "authorize" ? "authorize network access for" : "block network access for";
  if (!confirm(`Do you want to ${verb} this executable?\n\n${path}`)) return;
  const result = await postJson(url, { path });
  setMessage(result.ok ? result.output : result.error, !result.ok);
  refreshAll();
}

async function enforceAgents() {
  if (!confirm("Block outbound network access for all detected unapproved agent executables?")) return;
  const result = await postJson("/api/actions/enforce-agent-policy", {});
  setMessage(result.ok ? "Unapproved agent policy enforced." : result.error, !result.ok);
  refreshAll();
}

async function purgeLogs() {
  if (!confirm("Purge reviewed RoamSentinel alert/action logs now?")) return;
  const result = await postJson("/api/logs/purge", {});
  setMessage(result.ok ? result.output : result.error, !result.ok);
  refreshAll();
}

async function restoreAgent(path) {
  if (!path) return setMessage("Blocked agent path is unavailable.", true);
  if (!confirm(`Remove RoamSentinel's agent block for this executable?\n\n${path}`)) return;
  const result = await postJson("/api/actions/unblock-agent", { path });
  setMessage(result.ok ? "Agent block restored." : result.error, !result.ok);
  refreshAll();
}

async function restoreIp(ipAddress) {
  if (!ipAddress) return setMessage("Blocked IP is unavailable.", true);
  if (!confirm(`Remove RoamSentinel's Windows Firewall block for ${ipAddress}?`)) return;
  const result = await postJson("/api/actions/unblock-ip", { ipAddress });
  setMessage(result.ok ? `IP block restored for ${ipAddress}.` : result.error, !result.ok);
  refreshAll();
}

async function getJson(url) {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) throw new Error(await response.text());
  return response.json();
}

async function postJson(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  return response.json();
}

function rowsOrEmpty(items, colSpan, rowBuilder) {
  if (!items.length) {
    return `<tr><td colspan="${colSpan}" class="muted">No records in this view.</td></tr>`;
  }

  return items.map(rowBuilder).join("");
}

function yesNo(value) {
  return value ? "On" : "Off";
}

function formatMb(value) {
  if (value >= 1024) return `${(value / 1024).toFixed(2)} GB`;
  return `${Number(value || 0).toFixed(1)} MB`;
}

function formatCpu(value) {
  return `${Number(value || 0).toFixed(1)}%`;
}

function riskClass(score) {
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  if (score > 0) return "low";
  return "";
}

function severityClass(severity) {
  return `sev-${String(severity).toLowerCase()}`;
}

function setMessage(message, isError = false) {
  els.actionMessage.textContent = message || "";
  els.actionMessage.style.color = isError ? "var(--danger)" : "var(--muted)";
}

function formatTime(value) {
  if (!value) return "";
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    day: "2-digit",
    month: "short"
  }).format(new Date(value));
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#039;");
}
