const state = {
  activeView: "overview",
  activeWorkspace: "protect",
  refreshMs: 8000,
  memoryWarningPercent: 70,
  memoryDangerPercent: 85,
  highRiskScore: 70,
  mediumRiskScore: 40,
  csrfToken: sessionStorage.getItem("roamsentinel.csrfToken") || "",
  role: "Viewer",
  authenticated: false,
  mitreEvents: [],
  mitreTechniques: [],
  codeGateSubmissions: [],
  codeGateGitPushes: [],
  codeGateBundles: [],
  codeGateRules: [],
  agentEgressRules: [],
  mcpEvents: []
};

const mode = new URLSearchParams(window.location.search).get("mode");
const consoleMode = mode === "desktop" ? "Desktop Console" : "Browser Console";
document.documentElement.dataset.consoleMode = consoleMode;
document.querySelector("#consoleMode").textContent = `Mode: ${consoleMode}`;

const savedTheme = localStorage.getItem("roamsentinel.theme") || "system";
applyTheme(savedTheme);
document.querySelector("#themeToggle").addEventListener("click", cycleTheme);

let workspaceGroups = [
  {
    id: "protect",
    defaultView: "overview",
    label: "Protect",
    summary: "Endpoint defense",
    views: ["overview", "alerts", "deviceIntegrity", "malwareGuard", "processes", "connections"]
  },
  {
    id: "govern",
    defaultView: "agents",
    label: "Govern",
    summary: "AI & CodeGate",
    views: ["agents", "components", "mitre", "threatIntel"]
  },
  {
    id: "devops",
    defaultView: "devopsSummary",
    label: "DevOps",
    summary: "Fleet & sync",
    views: ["devopsSummary", "devopsClaims", "devopsCycles"]
  },
  {
    id: "admin",
    defaultView: "settings",
    label: "Admin",
    summary: "Audit & config",
    views: ["settings", "responseHistory", "auditLog", "mobileDevices", "appActivity"]
  }
];

let viewWorkspace = new Map(
  workspaceGroups.flatMap((group) => group.views.map((view) => [view, group.id]))
);

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
  overviewFirewall: document.querySelector("#overviewFirewall"),
  overviewAgents: document.querySelector("#overviewAgents"),
  overviewRisk: document.querySelector("#overviewRisk"),
  overviewScheduler: document.querySelector("#overviewScheduler"),
  overviewDatabase: document.querySelector("#overviewDatabase"),
  actionMessage: document.querySelector("#actionMessage"),
  operatorToken: document.querySelector("#operatorToken"),
  operatorState: document.querySelector("#operatorState"),
  alertsBody: document.querySelector("#alertsBody"),
  connectionsBody: document.querySelector("#connectionsBody"),
  processesBody: document.querySelector("#processesBody"),
  integrityDriverCount: document.querySelector("#integrityDriverCount"),
  integritySoftwareCount: document.querySelector("#integritySoftwareCount"),
  integrityPersistenceCount: document.querySelector("#integrityPersistenceCount"),
  integrityServiceCount: document.querySelector("#integrityServiceCount"),
  integrityTaskCount: document.querySelector("#integrityTaskCount"),
  integrityListenerCount: document.querySelector("#integrityListenerCount"),
  integrityPowerShell: document.querySelector("#integrityPowerShell"),
  integrityDriversBody: document.querySelector("#integrityDriversBody"),
  integrityPersistenceBody: document.querySelector("#integrityPersistenceBody"),
  integritySoftwareBody: document.querySelector("#integritySoftwareBody"),
  integrityFilesBody: document.querySelector("#integrityFilesBody"),
  integrityServicesBody: document.querySelector("#integrityServicesBody"),
  integrityTasksBody: document.querySelector("#integrityTasksBody"),
  integrityFirewallBody: document.querySelector("#integrityFirewallBody"),
  integrityListenersBody: document.querySelector("#integrityListenersBody"),
  integrityEventsBody: document.querySelector("#integrityEventsBody"),
  integrityFindingsBody: document.querySelector("#integrityFindingsBody"),
  mobileDeviceCount: document.querySelector("#mobileDeviceCount"),
  mobileFindingCount: document.querySelector("#mobileFindingCount"),
  mobileAppCount: document.querySelector("#mobileAppCount"),
  mobileNetworkCount: document.querySelector("#mobileNetworkCount"),
  mobilePolicySummary: document.querySelector("#mobilePolicySummary"),
  mobilePairingCode: document.querySelector("#mobilePairingCode"),
  mobilePairingQr: document.querySelector("#mobilePairingQr"),
  mobilePairingCommand: document.querySelector("#mobilePairingCommand"),
  copyMobilePairingPayload: document.querySelector("#copyMobilePairingPayload"),
  createMobilePairing: document.querySelector("#createMobilePairing"),
  mobileDevicesBody: document.querySelector("#mobileDevicesBody"),
  mobileAppsBody: document.querySelector("#mobileAppsBody"),
  mobileFindingsBody: document.querySelector("#mobileFindingsBody"),
  appActivityInstalledCount: document.querySelector("#appActivityInstalledCount"),
  appActivityActiveCount: document.querySelector("#appActivityActiveCount"),
  appActivityUnusedCount: document.querySelector("#appActivityUnusedCount"),
  appActivityUnusedActiveCount: document.querySelector("#appActivityUnusedActiveCount"),
  appActivityBody: document.querySelector("#appActivityBody"),
  malwareDefenderAv: document.querySelector("#malwareDefenderAv"),
  malwareDefenderRealtime: document.querySelector("#malwareDefenderRealtime"),
  malwareDetectionCount: document.querySelector("#malwareDetectionCount"),
  malwareSuspiciousFileCount: document.querySelector("#malwareSuspiciousFileCount"),
  malwareCapabilitiesBody: document.querySelector("#malwareCapabilitiesBody"),
  malwareDetectionsBody: document.querySelector("#malwareDetectionsBody"),
  malwareFilesBody: document.querySelector("#malwareFilesBody"),
  modulesBody: document.querySelector("#modulesBody"),
  insiderRiskScore: document.querySelector("#insiderRiskScore"),
  insiderRiskSeverity: document.querySelector("#insiderRiskSeverity"),
  insiderRiskSignals: document.querySelector("#insiderRiskSignals"),
  codeGateResult: document.querySelector("#codeGateResult"),
  codeGateDetailPanel: document.querySelector("#codeGateDetailPanel"),
  codeGateSubmissionsBody: document.querySelector("#codeGateSubmissionsBody"),
  codeGateGitPushesBody: document.querySelector("#codeGateGitPushesBody"),
  codeGateBundlesBody: document.querySelector("#codeGateBundlesBody"),
  codeGateRulesBody: document.querySelector("#codeGateRulesBody"),
  codeGateVerdictFilter: document.querySelector("#codeGateVerdictFilter"),
  codeGateRepositoryFilter: document.querySelector("#codeGateRepositoryFilter"),
  codeGateActorFilter: document.querySelector("#codeGateActorFilter"),
  codeGateBundleTypeFilter: document.querySelector("#codeGateBundleTypeFilter"),
  ramText: document.querySelector("#ramText"),
  ramBar: document.querySelector("#ramBar"),
  heavyMemoryCount: document.querySelector("#heavyMemoryCount"),
  heavyCpuCount: document.querySelector("#heavyCpuCount"),
  topMemoryBody: document.querySelector("#topMemoryBody"),
  topCpuBody: document.querySelector("#topCpuBody"),
  startupBody: document.querySelector("#startupBody"),
  scheduledTasksBody: document.querySelector("#scheduledTasksBody"),
  schedulerBody: document.querySelector("#schedulerBody"),
  schedulerSummary: document.querySelector("#schedulerSummary"),
  agentsBody: document.querySelector("#agentsBody"),
  agentEgressRulesBody: document.querySelector("#agentEgressRulesBody"),
  mcpTotalCount: document.querySelector("#mcpTotalCount"),
  mcpBlockedCount: document.querySelector("#mcpBlockedCount"),
  mcpWarnedCount: document.querySelector("#mcpWarnedCount"),
  mcpToolCount: document.querySelector("#mcpToolCount"),
  mcpEventsBody: document.querySelector("#mcpEventsBody"),
  threatProvidersBody: document.querySelector("#threatProvidersBody"),
  threatIndicatorsBody: document.querySelector("#threatIndicatorsBody"),
  threatLookupResult: document.querySelector("#threatLookupResult"),
  responseHistoryBody: document.querySelector("#responseHistoryBody"),
  auditLogBody: document.querySelector("#auditLogBody"),
  ruleSettingsBody: document.querySelector("#ruleSettingsBody"),
  settingProduct: document.querySelector("#settingProduct"),
  settingVersion: document.querySelector("#settingVersion"),
  settingBindUrl: document.querySelector("#settingBindUrl"),
  settingRefresh: document.querySelector("#settingRefresh"),
  settingTelemetry: document.querySelector("#settingTelemetry"),
  settingScheduler: document.querySelector("#settingScheduler"),
  settingRetention: document.querySelector("#settingRetention"),
  settingResponseAuth: document.querySelector("#settingResponseAuth"),
  settingMigration: document.querySelector("#settingMigration"),
  policyRulesBody: document.querySelector("#policyRulesBody"),
  authorizedAgentsBody: document.querySelector("#authorizedAgentsBody"),
  blockedAgentsBody: document.querySelector("#blockedAgentsBody"),
  blockedIpsBody: document.querySelector("#blockedIpsBody"),
  mitreEventCount: document.querySelector("#mitreEventCount"),
  mitreTacticCount: document.querySelector("#mitreTacticCount"),
  mitreTechniqueCount: document.querySelector("#mitreTechniqueCount"),
  mitreHostCount: document.querySelector("#mitreHostCount"),
  mitreTacticFilter: document.querySelector("#mitreTacticFilter"),
  mitreTechniqueFilter: document.querySelector("#mitreTechniqueFilter"),
  mitreSeverityFilter: document.querySelector("#mitreSeverityFilter"),
  mitreHostFilter: document.querySelector("#mitreHostFilter"),
  mitreEventsBody: document.querySelector("#mitreEventsBody"),
  mitreCatalogBody: document.querySelector("#mitreCatalogBody"),
  devopsNodeId: document.querySelector("#devopsNodeId"),
  devopsNodeRole: document.querySelector("#devopsNodeRole"),
  devopsPushStatus: document.querySelector("#devopsPushStatus"),
  devopsLastPush: document.querySelector("#devopsLastPush"),
  devopsPullStatus: document.querySelector("#devopsPullStatus"),
  devopsLastPull: document.querySelector("#devopsLastPull"),
  devopsAppCount: document.querySelector("#devopsAppCount"),
  devopsPushTableBody: document.querySelector("#devopsPushTableBody"),
  devopsClaimsBody: document.querySelector("#devopsClaimsBody"),
  devopsCyclesBody: document.querySelector("#devopsCyclesBody"),
  devopsReportsList: document.querySelector("#devopsReportsList")
};

document.querySelector(".workspace-nav")?.addEventListener("click", (event) => {
  const button = event.target.closest("[data-workspace]");
  if (button) switchWorkspace(button.dataset.workspace);
});
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
document.querySelector("#reviewLogs").addEventListener("click", () => switchView("alerts"));
document.querySelector("#enforceAgents").addEventListener("click", enforceAgents);
document.querySelector("#exportBackup").addEventListener("click", exportBackup);
document.querySelector("#blockForm").addEventListener("submit", blockIp);
document.querySelector("#quarantineForm").addEventListener("submit", quarantineFile);
document.querySelector("#operatorForm").addEventListener("submit", unlockResponses);
document.querySelector("#threatLookupForm").addEventListener("submit", lookupThreatIntel);
document.querySelector("#codeGateForm").addEventListener("submit", scanCodeGate);
document.querySelector("#exportCodeGateSubmissions").addEventListener("click", () => exportCodeGateReport("submissions"));
document.querySelector("#exportCodeGateGitPushes").addEventListener("click", () => exportCodeGateReport("git-pushes"));
document.querySelector("#exportCodeGateBundles").addEventListener("click", () => exportCodeGateReport("offline-bundles"));
document.querySelector("#resetMitreFilters").addEventListener("click", resetMitreFilters);
document.querySelector("#triggerPushSync")?.addEventListener("click", () => triggerDevOpsSync("push"));
document.querySelector("#triggerPullSync")?.addEventListener("click", () => triggerDevOpsSync("pull"));
els.createMobilePairing?.addEventListener("click", createMobilePairing);
els.copyMobilePairingPayload?.addEventListener("click", copyMobilePairingPayload);
[
  els.mitreTacticFilter,
  els.mitreTechniqueFilter,
  els.mitreSeverityFilter,
  els.mitreHostFilter
].forEach((control) => control.addEventListener("change", renderMitreTables));
[
  els.codeGateVerdictFilter,
  els.codeGateRepositoryFilter,
  els.codeGateActorFilter,
  els.codeGateBundleTypeFilter
].forEach((control) => control.addEventListener("input", renderCodeGateAuditTables));

state.mobilePairingPayload = "";

updateWorkspaceShell();
initialize();

function applyTheme(theme) {
  if (theme === "system") {
    delete document.documentElement.dataset.theme;
  } else {
    document.documentElement.dataset.theme = theme;
  }
  document.querySelector("#themeToggle").textContent =
    `Theme: ${theme[0].toUpperCase()}${theme.slice(1)}`;
}

function cycleTheme() {
  const current = localStorage.getItem("roamsentinel.theme") || "system";
  const next = current === "system" ? "dark" :
    current === "dark" ? "light" : "system";
  localStorage.setItem("roamsentinel.theme", next);
  applyTheme(next);
}

function switchWorkspace(workspace) {
  const group = workspaceGroups.find((item) => item.id === workspace);
  if (!group) return;
  state.activeWorkspace = group.id;
  const targetView = group.views.includes(state.activeView)
    ? state.activeView
    : group.defaultView;
  switchView(targetView, { preserveWorkspace: true });
}

function updateWorkspaceShell() {
  const activeGroup =
    workspaceGroups.find((group) => group.id === state.activeWorkspace) ||
    workspaceGroups[0];
  const visibleViews = new Set(activeGroup.views);
  document.querySelectorAll(".workspace-tab").forEach((tab) => {
    tab.classList.toggle("active", tab.dataset.workspace === activeGroup.id);
  });
  document.querySelectorAll(".tab").forEach((tab) => {
    const isVisible = visibleViews.has(tab.dataset.view);
    tab.hidden = !isVisible;
    tab.classList.toggle("active", tab.dataset.view === state.activeView);
  });

  const titleEl = document.querySelector("#activeWorkspaceTitle");
  if (titleEl) {
    titleEl.textContent = activeGroup.label || "Device Protection Center";
  }

  const workbenchEl = document.querySelector(".workbench");
  if (workbenchEl) {
    workbenchEl.classList.toggle("workspace-full-width", activeGroup.id !== "protect");
  }

  const dropdown = document.querySelector("#moduleSelector");
  if (dropdown && dropdown.value !== activeGroup.id) {
    dropdown.value = activeGroup.id;
  }
}

document.querySelector("#moduleSelector")?.addEventListener("change", (e) => {
  switchWorkspace(e.target.value);
});

async function initialize() {
  await refreshSession();
  try {
    const [config, moduleExperience] = await Promise.all([
      getJson("/api/dashboard/settings"),
      getJson("/api/v1/module-experiences")
    ]);
    applyModuleExperienceManifest(moduleExperience);
    state.refreshMs = Number(config.refreshIntervalMilliseconds) || state.refreshMs;
    state.memoryWarningPercent = Number(config.memoryWarningPercent) || state.memoryWarningPercent;
    state.memoryDangerPercent = Number(config.memoryDangerPercent) || state.memoryDangerPercent;
    state.highRiskScore = Number(config.highSeverityScore) || state.highRiskScore;
    state.mediumRiskScore = Number(config.mediumSeverityScore) || state.mediumRiskScore;
  } catch {
    // Safe local default remains active when configuration is unavailable.
  }

  await refreshAll();
  setInterval(refreshAll, state.refreshMs);
}

function applyModuleExperienceManifest(manifest) {
  const workspaces = Array.isArray(manifest?.workspaces)
    ? manifest.workspaces
    : [];
  if (workspaces.length === 0) return;

  workspaceGroups = workspaces.map((workspace) => ({
    id: workspace.id,
    label: workspace.label,
    summary: workspace.summary,
    defaultView: workspace.defaultView,
    views: workspace.views || []
  }));
  viewWorkspace = new Map(
    workspaceGroups.flatMap((group) =>
      (group.views || []).map((view) => [view, group.id])));
  if (!workspaceGroups.some((group) => group.id === state.activeWorkspace)) {
    state.activeWorkspace = workspaceGroups[0].id;
    state.activeView = workspaceGroups[0].defaultView;
  }
  renderWorkspaceNav();
  renderModuleDropdown();
  updateWorkspaceShell();
}

function renderWorkspaceNav() {
  const nav = document.querySelector(".workspace-nav");
  if (!nav) return;
  nav.innerHTML = workspaceGroups.map((workspace) => `
    <button class="workspace-tab" data-workspace="${escapeHtml(workspace.id)}" type="button">
      <span>${escapeHtml(workspace.label || workspace.id)}</span>
      <small>${escapeHtml(workspace.summary || "")}</small>
    </button>
  `).join("");
}

function renderModuleDropdown() {
  const dropdown = document.querySelector("#moduleSelector");
  if (!dropdown) return;
  dropdown.innerHTML = workspaceGroups.map((w) => `
    <option value="${escapeHtml(w.id)}">${escapeHtml(w.label || w.id)}</option>
  `).join("");
  dropdown.value = state.activeWorkspace;
}

function switchView(view, options = {}) {
  state.activeView = view;
  if (!options.preserveWorkspace) {
    state.activeWorkspace = viewWorkspace.get(view) || "overview";
  }
  updateWorkspaceShell();
  document.querySelectorAll(".view").forEach((panel) => panel.classList.toggle("active", panel.id === view));
  refreshView(view);
}

async function refreshAll() {
  try {
    const [overview, scheduler] = await Promise.all([
      getJson("/api/dashboard/security-overview"),
      getJson("/api/v1/scheduler")
    ]);
    const summary = overview.summary;
    els.adminState.textContent = summary.isAdministrator ? "Admin mode" : "Standard mode";
    els.adminState.style.background =
      summary.isAdministrator ? "var(--ok-soft)" : "var(--warning-soft)";
    els.connectionCount.textContent = summary.connectionCount;
    els.processCount.textContent = summary.processCount;
    els.startupCount.textContent = summary.startupEntryCount;
    els.alertCount.textContent =
      summary.criticalAlerts + summary.highAlerts +
      summary.mediumAlerts + summary.lowAlerts + summary.infoAlerts;
    els.highFindingCount.textContent =
      summary.criticalAlerts + summary.highAlerts;
    els.mediumFindingCount.textContent = summary.mediumAlerts;
    els.postureState.textContent =
      summary.criticalAlerts > 0 ? "Critical" :
      summary.highAlerts > 0 ? "Attention" :
      summary.mediumAlerts > 0 ? "Review" : "Stable";
    els.postureState.className =
      summary.criticalAlerts > 0 || summary.highAlerts > 0
        ? "state-danger"
        : summary.mediumAlerts > 0 ? "state-warning" : "state-ok";
    els.updatedAt.textContent = `Updated ${formatTime(summary.generatedAt)}`;
    renderDefender(summary.defender);
    renderOverview(overview, scheduler);
    if (state.activeView === "processes") {
      renderPerformance(overview.performance);
      renderProcesses(await getJson("/api/dashboard/live-processes"));
    } else if (state.activeView !== "overview") {
      refreshView(state.activeView);
    }
  } catch (error) {
    setMessage(error.message, true);
  }
}

async function refreshView(view) {
  if (view === "overview") return;
  if (view === "alerts") renderAlerts(await getJson("/api/dashboard/alerts"));
  if (view === "mitre") await loadMitre();
  if (view === "connections") renderConnections(await getJson("/api/dashboard/network-connections"));
  if (view === "components") {
    const [
      modules,
      insiderRisk,
      codeGateSubmissions,
      codeGateGitPushes,
      codeGateBundles,
      codeGateRules
    ] = await Promise.all([
      getJson("/api/modules"),
      getJson("/api/modules/insider-risk"),
      getJson("/api/v1/codegate/submissions?limit=25"),
      getJson("/api/v1/codegate/git-pushes?limit=25"),
      getJson("/api/v1/codegate/offline-bundles?limit=25"),
      getJson("/api/v1/codegate/rules")
    ]);
    renderComponents(
      modules,
      insiderRisk,
      codeGateSubmissions,
      codeGateGitPushes,
      codeGateBundles,
      codeGateRules);
  }
  if (view === "mobileDevices") renderMobileDevices(await getJson("/api/dashboard/mobile-devices"));
  if (view === "appActivity") renderAppActivity(await getJson("/api/dashboard/app-activity"));
  if (view === "malwareGuard") renderMalwareGuard(await getJson("/api/dashboard/malware-guard"));
  if (view === "deviceIntegrity") {
    const [snapshot, events, findings] = await Promise.all([
      getJson("/api/v1/device-integrity"),
      getJson("/api/v1/device-integrity/events?limit=100"),
      getJson("/api/v1/device-integrity/findings?limit=100")
    ]);
    renderDeviceIntegrity(snapshot, events, findings);
  }
  if (view === "processes") {
    const [overview, processes] = await Promise.all([
      getJson("/api/dashboard/security-overview"),
      getJson("/api/dashboard/live-processes")
    ]);
    renderPerformance(overview.performance);
    renderProcesses(processes);
  }
  if (view === "settings") {
    const [settings, scheduler, startup, scheduledTasks] = await Promise.all([
      getJson("/api/dashboard/settings"),
      getJson("/api/v1/scheduler"),
      getJson("/api/startup"),
      getJson("/api/scheduled-tasks")
    ]);
    renderSettings(settings, scheduler);
    renderStartup(startup);
    renderScheduledTasks(scheduledTasks);
  }
  if (view === "agents") {
    const [agentView, egressRules, mcpSummary] = await Promise.all([
      getJson("/api/dashboard/ai-agent-governance"),
      getJson("/api/v1/agents/egress-rules"),
      getJson("/api/v1/agents/mcp-summary")
    ]);
    renderAgents(agentView, egressRules, mcpSummary);
  }
  if (view === "threatIntel") renderThreatIntel(await getJson("/api/dashboard/threat-intel"));
  if (view === "responseHistory") renderResponseHistory(await getJson("/api/dashboard/response-history"));
  if (view === "auditLog") renderAuditLog(await getJson("/api/dashboard/audit-log"));
  if (view === "devopsSummary" || view === "devopsClaims" || view === "devopsCycles") {
    const summary = await getJson("/api/v1/devops/summary");
    renderDevOps(summary);
  }
}

async function loadMitre() {
  const response = await getJson("/api/dashboard/mitre-attack");
  state.mitreEvents = response.events || [];
  state.mitreTechniques = response.techniques || [];
  populateMitreFilters();
  renderMitreTables();
}

function renderComponents(
  modules,
  insiderRisk,
  codeGateSubmissions = [],
  codeGateGitPushes = [],
  codeGateBundles = [],
  codeGateRules = []) {
  els.modulesBody.innerHTML = rowsOrEmpty(modules || [], 4, (module) => `
    <tr>
      <td><strong>${escapeHtml(module.name)}</strong><br><span class="muted">${escapeHtml(module.id)}</span></td>
      <td>${escapeHtml(module.productComponent)}</td>
      <td><span class="risk ${module.status === "active" ? "low" : "medium"}">${escapeHtml(module.status)}</span></td>
      <td class="detail">${(module.capabilities || []).map(escapeHtml).join("<br>")}</td>
    </tr>
  `);

  els.insiderRiskScore.textContent = insiderRisk.riskScore ?? 0;
  els.insiderRiskSeverity.textContent = insiderRisk.severity || "info";
  els.insiderRiskSeverity.className =
    `risk ${severityClass(insiderRisk.severity || "info")}`;
  els.insiderRiskSignals.innerHTML = (insiderRisk.signals || [])
    .map(signal => `<li>${escapeHtml(signal)}</li>`)
    .join("");
  state.codeGateSubmissions = codeGateSubmissions || [];
  state.codeGateGitPushes = codeGateGitPushes || [];
  state.codeGateBundles = codeGateBundles || [];
  state.codeGateRules = codeGateRules || [];
  renderCodeGateAuditTables();
}

function renderCodeGateAuditTables() {
  const verdict = els.codeGateVerdictFilter.value;
  const repository = els.codeGateRepositoryFilter.value.trim().toLowerCase();
  const actor = els.codeGateActorFilter.value.trim().toLowerCase();
  const bundleType = els.codeGateBundleTypeFilter.value;
  const submissions = state.codeGateSubmissions.filter((submission) =>
    !verdict || submission.verdict === verdict);
  const gitPushes = state.codeGateGitPushes.filter((push) =>
    (!verdict || push.verdict === verdict) &&
    (!repository || String(push.repositoryName || "").toLowerCase().includes(repository)) &&
    (!actor || String(push.actor || "").toLowerCase().includes(actor)));
  const bundles = state.codeGateBundles.filter((bundle) =>
    !bundleType || bundle.bundleType === bundleType);

  els.codeGateSubmissionsBody.innerHTML = rowsOrEmpty(
    submissions,
    7,
    (submission) => `
      <tr>
        <td>${formatTime(submission.evaluatedAt)}</td>
        <td><span class="risk ${riskClass(submission.riskScore)}">${escapeHtml(submission.verdict)}</span></td>
        <td>${escapeHtml(submission.riskScore)}</td>
        <td>${escapeHtml(submission.source)}<br><span class="muted">${escapeHtml(submission.revision)}</span></td>
        <td class="detail">${escapeHtml(submission.importPath)}</td>
        <td>${(submission.findings || []).length}</td>
        <td><button class="mini-button" type="button" data-codegate-submission="${escapeHtml(submission.submissionId)}">Details</button></td>
      </tr>`);
  els.codeGateGitPushesBody.innerHTML = rowsOrEmpty(
    gitPushes,
    7,
    (push) => `
      <tr>
        <td>${formatTime(push.observedAt)}</td>
        <td>${escapeHtml(push.repositoryName)}<br><span class="muted">${escapeHtml(push.newRevision)}</span></td>
        <td>${escapeHtml(push.branch || push.refName)}</td>
        <td>${escapeHtml(push.actor)}</td>
        <td><span class="risk ${riskClass(push.riskScore)}">${escapeHtml(push.verdict)}</span></td>
        <td>${(push.changedFiles || []).length}</td>
        <td><button class="mini-button" type="button" data-codegate-git-push="${escapeHtml(push.auditId)}">Details</button></td>
      </tr>`);
  els.codeGateBundlesBody.innerHTML = rowsOrEmpty(
    bundles,
    6,
    (bundle) => `
      <tr>
        <td>${formatTime(bundle.importedAt)}</td>
        <td>${escapeHtml(bundle.bundleType)}</td>
        <td>${escapeHtml(bundle.name)}<br><span class="muted">${escapeHtml(bundle.source)}</span></td>
        <td>${escapeHtml(bundle.version)}</td>
        <td>${formatTime(bundle.generatedAt)}</td>
        <td><span class="risk ${bundle.verified ? "low" : "medium"}">${escapeHtml(bundle.status)}</span></td>
      </tr>`);
  if (els.codeGateRulesBody) {
    els.codeGateRulesBody.innerHTML = rowsOrEmpty(
      state.codeGateRules || [],
      7,
      (rule) => `
        <tr>
          <td><code>${escapeHtml(rule.ruleId)}</code></td>
          <td><strong>${escapeHtml(rule.name)}</strong></td>
          <td><span class="risk ${riskClass(rule.riskScore)}">${escapeHtml(rule.severity)}</span></td>
          <td>${rule.riskScore}</td>
          <td><code>${escapeHtml(rule.pattern)}</code></td>
          <td class="detail">${escapeHtml(rule.explanation)}</td>
          <td><span class="risk ${rule.enabled ? "low" : "medium"}">${rule.enabled ? "Active" : "Disabled"}</span></td>
        </tr>`);
  }
  els.codeGateSubmissionsBody.querySelectorAll("[data-codegate-submission]").forEach((button) => {
    button.addEventListener("click", () => loadCodeGateSubmissionDetail(button.dataset.codegateSubmission));
  });
  els.codeGateGitPushesBody.querySelectorAll("[data-codegate-git-push]").forEach((button) => {
    button.addEventListener("click", () => loadCodeGateGitPushDetail(button.dataset.codegateGitPush));
  });
}

function renderDeviceIntegrity(snapshot, events, findings = []) {
  const drivers = snapshot.drivers || [];
  const software = snapshot.installedSoftware || [];
  const persistence = snapshot.registryPersistence || [];
  const files = snapshot.monitoredFiles || [];
  const services = snapshot.services || [];
  const tasks = snapshot.scheduledTasks || [];
  const firewall = snapshot.firewallProfiles || [];
  const listeners = snapshot.networkListeners || [];
  const powerShell = snapshot.powerShell || {};
  els.integrityDriverCount.textContent = drivers.length;
  els.integritySoftwareCount.textContent = software.length;
  els.integrityPersistenceCount.textContent = persistence.length;
  els.integrityServiceCount.textContent = services.length;
  els.integrityTaskCount.textContent = tasks.length;
  els.integrityListenerCount.textContent = listeners.length;
  els.integrityPowerShell.textContent =
    powerShell.executionPolicy || "Unavailable";
  els.integrityDriversBody.innerHTML = rowsOrEmpty(drivers, 5, (item) => `
    <tr><td>${escapeHtml(item.displayName || item.name)}</td>
    <td>${escapeHtml(item.state)}</td><td>${escapeHtml(item.startMode)}</td>
    <td>${escapeHtml(item.serviceType)}</td><td>${escapeHtml(item.path)}</td></tr>`);
  els.integrityPersistenceBody.innerHTML = rowsOrEmpty(persistence, 4, (item) => `
    <tr><td>${escapeHtml(item.hive)}</td><td>${escapeHtml(item.key)}</td>
    <td>${escapeHtml(item.name)}</td><td>${escapeHtml(item.value)}</td></tr>`);
  els.integritySoftwareBody.innerHTML = rowsOrEmpty(software, 4, (item) => `
    <tr><td>${escapeHtml(item.name)}</td><td>${escapeHtml(item.version)}</td>
    <td>${escapeHtml(item.publisher)}</td><td>${escapeHtml(item.installLocation)}</td></tr>`);
  els.integrityFilesBody.innerHTML = rowsOrEmpty(files, 4, (item) => `
    <tr><td>${escapeHtml(item.path)}</td><td>${formatBytes(item.length)}</td>
    <td>${formatTime(item.lastWriteTime)}</td><td>${escapeHtml(item.extension)}</td></tr>`);
  els.integrityServicesBody.innerHTML = rowsOrEmpty(services, 5, (item) => `
    <tr><td>${escapeHtml(item.displayName || item.name)}</td>
    <td>${escapeHtml(item.state)}</td><td>${escapeHtml(item.startMode)}</td>
    <td>${escapeHtml(item.account)}</td><td>${escapeHtml(item.path)}</td></tr>`);
  els.integrityTasksBody.innerHTML = rowsOrEmpty(tasks, 5, (item) => `
    <tr><td>${escapeHtml(`${item.path || ""}${item.name || ""}`)}</td>
    <td>${escapeHtml(item.state)}</td><td>${item.enabled ? "Yes" : "No"}</td>
    <td>${escapeHtml([item.command, item.arguments].filter(Boolean).join(" "))}</td>
    <td>${escapeHtml(item.trigger)}</td></tr>`);
  els.integrityFirewallBody.innerHTML = rowsOrEmpty(firewall, 5, (item) => `
    <tr><td>${escapeHtml(item.name)}</td><td>${item.enabled ? "Enabled" : "Disabled"}</td>
    <td>${escapeHtml(item.defaultInboundAction)}</td>
    <td>${escapeHtml(item.defaultOutboundAction)}</td>
    <td>${item.notificationsDisabled ? "Disabled" : "Enabled"}</td></tr>`);
  els.integrityListenersBody.innerHTML = rowsOrEmpty(listeners, 5, (item) => `
    <tr><td>${escapeHtml(item.protocol)}</td>
    <td>${escapeHtml(item.localAddress)}:${escapeHtml(item.localPort)}</td>
    <td>${escapeHtml(item.processId)}</td><td>${escapeHtml(item.processName)}</td>
    <td>${escapeHtml(item.processPath)}</td></tr>`);
  els.integrityEventsBody.innerHTML = rowsOrEmpty(events || [], 5, (item) => `
    <tr><td>${formatTime(item.observedAt)}</td><td>${escapeHtml(item.entityType)}</td>
    <td><span class="severity sev-${item.changeType === "removed" ? "high" : "info"}">${escapeHtml(item.changeType)}</span></td>
    <td>${escapeHtml(item.entityKey)}</td><td>${escapeHtml(item.explanation)}</td></tr>`);
  els.integrityFindingsBody.innerHTML = rowsOrEmpty(findings || [], 5, (item) => `
    <tr><td><span class="risk ${severityClass(item.severity)}">${escapeHtml(item.severity)}</span></td>
    <td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.title)}</td>
    <td>${escapeHtml(item.entityType)}<br><span class="muted">${escapeHtml(item.entityKey)}</span></td>
    <td>${escapeHtml(item.explanation)}</td></tr>`);
  if ((snapshot.collectionErrors || []).length) {
    setMessage(snapshot.collectionErrors.join("; "), true);
  }
}

function renderMobileDevices(view) {
  const devices = view.devices || [];
  const apps = view.recentApps || [];
  const findings = view.findings || [];
  const networkEvents = view.networkEvents || [];
  const policy = view.policy || {};
  els.mobileDeviceCount.textContent = devices.length;
  els.mobileFindingCount.textContent = findings.length;
  els.mobileAppCount.textContent = apps.length;
  els.mobileNetworkCount.textContent = networkEvents.length;
  els.mobilePolicySummary.textContent = `VPN required: ${yesNo(policy.requireVpn)} | Sideload alerts: ${yesNo(policy.alertOnSideloadedApps)} | Developer-mode alerts: ${yesNo(policy.alertOnDeveloperMode)}`;
  els.mobileDevicesBody.innerHTML = rowsOrEmpty(devices, 6, (device) => `
    <tr>
      <td><span class="risk ${device.status === "blocked" ? "critical" : device.status === "trusted" ? "low" : riskClass(device.riskScore)}">${escapeHtml(device.status)}</span></td>
      <td><strong>${escapeHtml(device.displayName || device.deviceId)}</strong><br><span class="muted">${escapeHtml(device.manufacturer)} ${escapeHtml(device.model)}</span></td>
      <td>${escapeHtml(device.platform)}<br><span class="muted">${escapeHtml(device.osVersion)} | app ${escapeHtml(device.appVersion)}</span></td>
      <td>${formatTime(device.lastHeartbeatAt || device.lastSeenAt)}</td>
      <td><span class="risk ${riskClass(device.riskScore)}">${device.riskScore}</span></td>
      <td class="detail">${escapeHtml(device.riskReason)}</td>
    </tr>
  `);
  els.mobileAppsBody.innerHTML = rowsOrEmpty(apps, 5, (app) => `
    <tr>
      <td class="path">${escapeHtml(app.packageName)}</td>
      <td>${escapeHtml(app.appName)}</td>
      <td>${escapeHtml(app.versionName)}</td>
      <td>${escapeHtml(app.installerPackage || "unknown")}</td>
      <td>${app.systemApp ? "System" : "User"}${app.sideloaded ? " | Sideloaded" : ""}<br><span class="muted">${(app.requestedPermissions || []).length} permission(s)</span></td>
    </tr>
  `);
  els.mobileFindingsBody.innerHTML = rowsOrEmpty(findings, 5, (finding) => `
    <tr>
      <td><span class="severity ${severityClass(finding.severity)}">${escapeHtml(finding.severity)}</span></td>
      <td>${escapeHtml(finding.category)}</td>
      <td>${escapeHtml(finding.title)}<br><span class="muted">${escapeHtml(finding.detail)}</span></td>
      <td>${escapeHtml(finding.entityType)}<br><span class="muted">${escapeHtml(finding.entityId)}</span></td>
      <td>${formatTime(finding.observedAt)}</td>
    </tr>
  `);
}

async function createMobilePairing() {
  if (!confirm("Create a 10-minute pairing code for an Android companion device?")) return;
  const result = await postJson("/api/mobile-bridge/pairing-sessions", {});
  if (result.error) {
    setMessage(result.error, true);
    return;
  }

  els.mobilePairingCode.innerHTML = `Pairing code: <strong>${escapeHtml(result.pairingCode)}</strong> | Expires ${formatTime(result.expiresAt)}`;
  if (els.mobilePairingCommand) {
    els.mobilePairingCommand.textContent = [
      "powershell -NoProfile -ExecutionPolicy Bypass -File \"$env:ProgramFiles\\RoamSentinel\\scripts\\Register-RoamSentinelMobileDevice.ps1\" `",
      `  -PairingCode ${result.pairingCode} \``,
      "  -DeviceId android-test-1 `",
      "  -DisplayName \"My Android Phone\" `",
      "  -Platform Android"
    ].join("\n");
  }
  renderMobilePairingQr(result);
  setMessage("Mobile pairing code created.");
  renderMobileDevices(await getJson("/api/dashboard/mobile-devices"));
}

async function copyMobilePairingPayload() {
  if (!state.mobilePairingPayload) return;
  try {
    await navigator.clipboard.writeText(state.mobilePairingPayload);
    setMessage("Mobile scan payload copied.");
  } catch {
    setMessage("Copy failed. Select and copy the scan payload manually.", true);
  }
}

function renderMobilePairingQr(session) {
  if (!els.mobilePairingQr) return;
  const payload = session.pairingPayload ||
    `rs://pair?c=${encodeURIComponent(session.pairingCode)}&b=${encodeURIComponent(location.origin)}`;
  state.mobilePairingPayload = payload;
  if (els.copyMobilePairingPayload) {
    els.copyMobilePairingPayload.disabled = false;
  }
  const svg = createQrSvg(payload);
  els.mobilePairingQr.innerHTML = `
    <div class="qr-code">${svg}</div>
    <div class="qr-meta">
      <strong>Scan pairing payload</strong>
      <span>Temporary code only. Expires ${formatTime(session.expiresAt)}.</span>
      <span class="path">${escapeHtml(payload)}</span>
    </div>
  `;
}

function createQrSvg(text) {
  const qr = createByteQrVersion4Low(text);
  const quiet = 4;
  const scale = 6;
  const size = qr.length + quiet * 2;
  const rects = [];
  for (let y = 0; y < qr.length; y += 1) {
    for (let x = 0; x < qr.length; x += 1) {
      if (qr[y][x]) {
        rects.push(`<rect x="${x + quiet}" y="${y + quiet}" width="1" height="1"/>`);
      }
    }
  }

  return `<svg viewBox="0 0 ${size} ${size}" width="${size * scale}" height="${size * scale}" role="img" aria-label="RoamSentinel mobile pairing QR"><rect width="100%" height="100%" fill="white"/>` +
    `<g fill="black">${rects.join("")}</g></svg>`;
}

function createByteQrVersion4Low(text) {
  const version = 4;
  const size = 17 + version * 4;
  const dataCodewords = 80;
  const eccCodewords = 20;
  const bytes = Array.from(new TextEncoder().encode(text));
  if (bytes.length > 78) {
    throw new Error("Pairing QR payload is too long.");
  }

  const bits = [0, 1, 0, 0];
  pushBits(bits, bytes.length, 8);
  bytes.forEach((value) => pushBits(bits, value, 8));
  const capacity = dataCodewords * 8;
  for (let i = 0; i < 4 && bits.length < capacity; i += 1) bits.push(0);
  while (bits.length % 8 !== 0) bits.push(0);
  const data = [];
  for (let i = 0; i < bits.length; i += 8) {
    data.push(bitsToByte(bits.slice(i, i + 8)));
  }
  for (let pad = 0xec; data.length < dataCodewords; pad ^= 0xfd) {
    data.push(pad);
  }

  const codewords = data.concat(reedSolomonRemainder(data, eccCodewords));
  const modules = Array.from({ length: size }, () => Array(size).fill(false));
  const reserved = Array.from({ length: size }, () => Array(size).fill(false));
  drawFunctionPatterns(modules, reserved, version);
  drawCodewords(modules, reserved, codewords);
  drawFormatBits(modules, reserved, 1, 0);
  return modules;
}

function pushBits(bits, value, count) {
  for (let i = count - 1; i >= 0; i -= 1) {
    bits.push((value >>> i) & 1);
  }
}

function bitsToByte(bits) {
  return bits.reduce((value, bit) => (value << 1) | bit, 0);
}

function drawFunctionPatterns(modules, reserved, version) {
  const size = modules.length;
  drawFinder(modules, reserved, 0, 0);
  drawFinder(modules, reserved, size - 7, 0);
  drawFinder(modules, reserved, 0, size - 7);
  for (let i = 8; i < size - 8; i += 1) {
    setFunction(modules, reserved, i, 6, i % 2 === 0);
    setFunction(modules, reserved, 6, i, i % 2 === 0);
  }
  drawAlignment(modules, reserved, 26, 26);
  setFunction(modules, reserved, 8, 4 * version + 9, true);
  reserveFormatAreas(reserved);
}

function drawFinder(modules, reserved, left, top) {
  for (let y = -1; y <= 7; y += 1) {
    for (let x = -1; x <= 7; x += 1) {
      const xx = left + x;
      const yy = top + y;
      if (yy < 0 || yy >= modules.length || xx < 0 || xx >= modules.length) continue;
      const dark = x >= 0 && x <= 6 && y >= 0 && y <= 6 &&
        (x === 0 || x === 6 || y === 0 || y === 6 || (x >= 2 && x <= 4 && y >= 2 && y <= 4));
      setFunction(modules, reserved, xx, yy, dark);
    }
  }
}

function drawAlignment(modules, reserved, centerX, centerY) {
  for (let y = -2; y <= 2; y += 1) {
    for (let x = -2; x <= 2; x += 1) {
      setFunction(
        modules,
        reserved,
        centerX + x,
        centerY + y,
        Math.max(Math.abs(x), Math.abs(y)) !== 1);
    }
  }
}

function reserveFormatAreas(reserved) {
  const size = reserved.length;
  for (let i = 0; i < 9; i += 1) {
    if (i !== 6) {
      reserved[8][i] = true;
      reserved[i][8] = true;
    }
  }
  for (let i = 0; i < 8; i += 1) {
    reserved[8][size - 1 - i] = true;
    reserved[size - 1 - i][8] = true;
  }
}

function setFunction(modules, reserved, x, y, dark) {
  modules[y][x] = dark;
  reserved[y][x] = true;
}

function drawCodewords(modules, reserved, codewords) {
  const size = modules.length;
  const bits = codewords.flatMap((value) =>
    Array.from({ length: 8 }, (_, index) => (value >>> (7 - index)) & 1));
  let bitIndex = 0;
  let upward = true;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right -= 1;
    for (let vertical = 0; vertical < size; vertical += 1) {
      const y = upward ? size - 1 - vertical : vertical;
      for (let dx = 0; dx < 2; dx += 1) {
        const x = right - dx;
        if (reserved[y][x]) continue;
        const raw = bitIndex < bits.length ? bits[bitIndex] === 1 : false;
        const masked = raw !== ((x + y) % 2 === 0);
        modules[y][x] = masked;
        bitIndex += 1;
      }
    }
    upward = !upward;
  }
}

function drawFormatBits(modules, reserved, eccLevel, mask) {
  const size = modules.length;
  const bits = formatBits(eccLevel, mask);
  for (let i = 0; i <= 5; i += 1) setFunction(modules, reserved, 8, i, ((bits >>> i) & 1) !== 0);
  setFunction(modules, reserved, 8, 7, ((bits >>> 6) & 1) !== 0);
  setFunction(modules, reserved, 8, 8, ((bits >>> 7) & 1) !== 0);
  setFunction(modules, reserved, 7, 8, ((bits >>> 8) & 1) !== 0);
  for (let i = 9; i < 15; i += 1) setFunction(modules, reserved, 14 - i, 8, ((bits >>> i) & 1) !== 0);
  for (let i = 0; i < 8; i += 1) setFunction(modules, reserved, size - 1 - i, 8, ((bits >>> i) & 1) !== 0);
  for (let i = 8; i < 15; i += 1) setFunction(modules, reserved, 8, size - 15 + i, ((bits >>> i) & 1) !== 0);
}

function formatBits(eccLevel, mask) {
  const data = (eccLevel << 3) | mask;
  let value = data << 10;
  for (let i = 14; i >= 10; i -= 1) {
    if (((value >>> i) & 1) !== 0) {
      value ^= 0x537 << (i - 10);
    }
  }
  return ((data << 10) | value) ^ 0x5412;
}

function reedSolomonRemainder(data, degree) {
  const generator = reedSolomonGenerator(degree);
  const result = Array(degree).fill(0);
  data.forEach((value) => {
    const factor = value ^ result.shift();
    result.push(0);
    generator.slice(1).forEach((coefficient, index) => {
      result[index] ^= gfMultiply(coefficient, factor);
    });
  });
  return result;
}

function reedSolomonGenerator(degree) {
  let result = [1];
  for (let i = 0; i < degree; i += 1) {
    const next = Array(result.length + 1).fill(0);
    result.forEach((coefficient, index) => {
      next[index] ^= gfMultiply(coefficient, 1);
      next[index + 1] ^= gfMultiply(coefficient, gfPow(2, i));
    });
    result = next;
  }
  return result;
}

function gfPow(value, exponent) {
  let result = 1;
  for (let i = 0; i < exponent; i += 1) {
    result = gfMultiply(result, value);
  }
  return result;
}

function gfMultiply(left, right) {
  let result = 0;
  for (let i = 0; i < 8; i += 1) {
    if ((right & 1) !== 0) result ^= left;
    const carry = (left & 0x80) !== 0;
    left = (left << 1) & 0xff;
    if (carry) left ^= 0x1d;
    right >>>= 1;
  }
  return result;
}

function renderAppActivity(view) {
  const apps = view.apps || [];
  els.appActivityInstalledCount.textContent = view.installedAppCount ?? apps.length;
  els.appActivityActiveCount.textContent = view.activeAppCount ?? 0;
  els.appActivityUnusedCount.textContent = view.unusedAppCount ?? 0;
  els.appActivityUnusedActiveCount.textContent = view.unusedButActiveCount ?? 0;
  els.appActivityBody.innerHTML = rowsOrEmpty(apps, 7, (app) => `
    <tr>
      <td><span class="risk ${activityClass(app.recommendation, app.riskScore)}">${escapeHtml(app.recommendation)}</span></td>
      <td><strong>${escapeHtml(app.name)}</strong><br><span class="muted path">${escapeHtml(app.installLocation || "")}</span></td>
      <td>${escapeHtml(app.publisher || "-")}<br><span class="muted">${escapeHtml(app.version || "")}</span></td>
      <td>${app.lastSeenRunningAt ? formatTime(app.lastSeenRunningAt) : "Not observed"}<br><span class="muted">${app.daysSinceLastUse ?? "-"} day(s)</span></td>
      <td>${app.currentProcessCount || 0} process(es)<br><span class="muted">${app.currentNetworkConnectionCount || 0} network flow(s)${app.autoStart ? " | autostart" : ""}</span></td>
      <td><span class="risk ${riskClass(app.riskScore)}">${app.riskScore}</span></td>
      <td class="detail">${escapeHtml(app.riskReason)}</td>
    </tr>
  `);
}

function renderMalwareGuard(view) {
  const defender = view.defender || {};
  const detections = view.recentDetections || [];
  const files = view.suspiciousFiles || [];
  const capabilities = view.capabilities || [];
  els.malwareDefenderAv.textContent = yesNo(defender.antivirusEnabled);
  els.malwareDefenderRealtime.textContent = yesNo(defender.realTimeProtectionEnabled);
  els.malwareDetectionCount.textContent = detections.length;
  els.malwareSuspiciousFileCount.textContent = files.length;
  els.malwareCapabilitiesBody.innerHTML = rowsOrEmpty(capabilities, 3, (capability) => `
    <tr>
      <td>${escapeHtml(capability.name)}</td>
      <td><span class="risk ${capability.status === "available" ? "low" : capability.status === "planned" ? "" : "medium"}">${escapeHtml(capability.status)}</span></td>
      <td class="detail">${escapeHtml(capability.detail)}</td>
    </tr>
  `);
  els.malwareDetectionsBody.innerHTML = rowsOrEmpty(detections, 4, (item) => `
    <tr>
      <td>${formatTime(item.detectedAt)}</td>
      <td>${escapeHtml(item.threatName || "Unknown threat")}<br><span class="muted">${escapeHtml(item.source)}</span></td>
      <td>${escapeHtml(item.action)}<br><span class="muted">${escapeHtml(item.status)}</span></td>
      <td class="path">${escapeHtml(item.resource)}</td>
    </tr>
  `);
  els.malwareFilesBody.innerHTML = rowsOrEmpty(files, 4, (item) => `
    <tr>
      <td><span class="risk ${riskClass(item.riskScore)}">${item.riskScore}</span></td>
      <td class="path">${escapeHtml(item.path)}</td>
      <td class="path">${escapeHtml(item.sha256 || item.reputation)}</td>
      <td class="detail">${escapeHtml(item.reason)}</td>
    </tr>
  `);
}

function populateMitreFilters() {
  const selectedTactic = els.mitreTacticFilter.value;
  const selectedTechnique = els.mitreTechniqueFilter.value;
  const selectedHost = els.mitreHostFilter.value;
  const tactics = uniqueValues(state.mitreEvents.map((event) => event.tactic));
  const hosts = uniqueValues(state.mitreEvents.map((event) => event.host));

  els.mitreTacticFilter.innerHTML =
    optionList("All tactics", tactics, selectedTactic);
  els.mitreTechniqueFilter.innerHTML =
    `<option value="">All techniques</option>` +
    state.mitreTechniques.map((technique) => `
      <option value="${escapeHtml(technique.techniqueId)}" ${
        technique.techniqueId === selectedTechnique ? "selected" : ""
      }>${escapeHtml(technique.techniqueId)} ${escapeHtml(technique.name)}</option>
    `).join("");
  els.mitreHostFilter.innerHTML =
    optionList("All hosts", hosts, selectedHost);
}

function renderMitreTables() {
  const tactic = els.mitreTacticFilter.value;
  const technique = els.mitreTechniqueFilter.value;
  const severity = els.mitreSeverityFilter.value;
  const host = els.mitreHostFilter.value;
  const events = state.mitreEvents.filter((event) =>
    (!tactic || event.tactic === tactic) &&
    (!technique || event.techniqueId === technique) &&
    (!severity || event.severity === severity) &&
    (!host || event.host === host)
  );

  els.mitreEventCount.textContent = events.length;
  els.mitreTacticCount.textContent =
    uniqueValues(events.map((event) => event.tactic)).length;
  els.mitreTechniqueCount.textContent =
    uniqueValues(events.map((event) => event.techniqueId)).length;
  els.mitreHostCount.textContent =
    uniqueValues(events.map((event) => event.host)).length;
  els.mitreEventsBody.innerHTML = rowsOrEmpty(events, 8, (event) => `
    <tr>
      <td>${escapeHtml(event.tactic)}</td>
      <td><strong>${escapeHtml(event.techniqueId)}</strong><br>${escapeHtml(event.techniqueName)}</td>
      <td><span class="risk ${severityClass(event.severity)}">${escapeHtml(event.severity)}</span></td>
      <td>${escapeHtml(event.host)}</td>
      <td>${formatTime(event.lastSeenAt)}</td>
      <td class="detail">${escapeHtml(event.title)}</td>
      <td>${event.occurrenceCount}</td>
      <td>${escapeHtml(event.mappingType)}</td>
    </tr>
  `);
  els.mitreCatalogBody.innerHTML = rowsOrEmpty(
    state.mitreTechniques,
    5,
    (technique) => `
      <tr>
        <td><strong>${escapeHtml(technique.techniqueId)}</strong></td>
        <td>${escapeHtml(technique.name)}</td>
        <td>${escapeHtml(technique.primaryTactic)}</td>
        <td>${escapeHtml(technique.status)}</td>
        <td>${escapeHtml(technique.replacedBy || "-")}</td>
      </tr>
    `
  );
}

function resetMitreFilters() {
  els.mitreTacticFilter.value = "";
  els.mitreTechniqueFilter.value = "";
  els.mitreSeverityFilter.value = "";
  els.mitreHostFilter.value = "";
  renderMitreTables();
}

function uniqueValues(values) {
  return [...new Set(values.filter(Boolean))]
    .sort((a, b) => a.localeCompare(b));
}

function optionList(allLabel, values, selected) {
  return `<option value="">${escapeHtml(allLabel)}</option>` +
    values.map((value) => `
      <option value="${escapeHtml(value)}" ${
        value === selected ? "selected" : ""
      }>${escapeHtml(value)}</option>
    `).join("");
}

function renderOverview(overview, scheduler) {
  renderPerformanceSummary(overview.performance);
  els.overviewFirewall.textContent = overview.firewall.anyProfileEnabled
    ? "Enabled"
    : "Needs review";
  els.overviewFirewall.className = overview.firewall.anyProfileEnabled
    ? "state-ok"
    : "state-danger";
  els.overviewAgents.textContent = overview.governedAgentCount;
  els.overviewRisk.textContent = overview.detection.overallRiskScore;
  els.overviewRisk.className =
    overview.detection.overallRiskScore >= state.highRiskScore
      ? "state-danger"
      : overview.detection.overallRiskScore >= state.mediumRiskScore
        ? "state-warning"
        : "state-ok";
  renderSchedulerSummary(scheduler);
  els.overviewDatabase.textContent =
    `v${overview.database.latestMigration}`;
}

function renderSchedulerSummary(scheduler) {
  const failed = (scheduler.tasks || [])
    .filter(task => task.enabled && task.lastStatus === "failed")
    .length;
  const running = (scheduler.tasks || [])
    .filter(task => task.enabled && task.lastStatus === "running")
    .length;
  els.overviewScheduler.textContent = !scheduler.enabled
    ? "Off"
    : failed > 0
      ? `${failed} issue${failed === 1 ? "" : "s"}`
      : running > 0
        ? "Running"
        : "On";
  els.overviewScheduler.className = !scheduler.enabled || failed > 0
    ? "state-warning"
    : "state-ok";
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
  els.alertsBody.innerHTML = rowsOrEmpty(alerts, 6, (alert) => `
    <tr>
      <td><span class="risk ${severityClass(alert.severity)}">${escapeHtml(alert.severity)}</span></td>
      <td>${escapeHtml(alert.category)}</td>
      <td>${escapeHtml(alert.title)}</td>
      <td class="detail">${escapeHtml(alert.detail)}</td>
      <td>${formatTime(alert.timestamp)}</td>
      <td class="button-row">
        <button class="mini-button allow" type="button" data-resolve-alert="${escapeHtml(alert.id)}">Resolve</button>
        <button class="mini-button" type="button" data-false-positive="${escapeHtml(alert.id)}">False positive</button>
      </td>
    </tr>
  `);
  els.alertsBody.querySelectorAll("[data-resolve-alert]").forEach((button) => {
    button.addEventListener("click", () => setAlertDisposition(button.dataset.resolveAlert, "resolve"));
  });
  els.alertsBody.querySelectorAll("[data-false-positive]").forEach((button) => {
    button.addEventListener("click", () => setAlertDisposition(button.dataset.falsePositive, "false-positive"));
  });
}

function renderThreatIntel(view) {
  els.threatProvidersBody.innerHTML = rowsOrEmpty(
    view.providers || [],
    4,
    (provider) => `
    <tr>
      <td>${escapeHtml(provider.name)}</td>
      <td>${provider.enabled ? "Enabled" : "Disabled"}</td>
      <td><span class="risk ${provider.configured ? "low" : "medium"}">${provider.configured ? "Ready" : "Not configured"}</span></td>
      <td>${escapeHtml((provider.supportedIndicatorTypes || []).join(", "))}</td>
    </tr>
  `);
  els.threatIndicatorsBody.innerHTML = rowsOrEmpty(
    view.indicators || [],
    7,
    (indicator) => `
      <tr>
        <td class="path">${escapeHtml(indicator.indicator)}</td>
        <td>${escapeHtml(indicator.indicatorType)}</td>
        <td><span class="risk ${reputationClass(indicator.reputation)}">${escapeHtml(indicator.reputation)}</span></td>
        <td>${indicator.confidence}</td>
        <td>${escapeHtml(indicator.source)}</td>
        <td>${formatTime(indicator.lastSeenAt)}</td>
        <td class="detail">${escapeHtml(indicator.description || "")}</td>
      </tr>
    `);
}

function renderResponseHistory(actions) {
  els.responseHistoryBody.innerHTML = rowsOrEmpty(actions, 8, (action) => `
    <tr>
      <td>${formatTime(action.requestedAt)}</td>
      <td>${escapeHtml(action.actionType)}</td>
      <td class="path">${escapeHtml(action.target)}</td>
      <td><span class="risk ${action.success ? "low" : "high"}">${escapeHtml(action.status)}</span></td>
      <td>${escapeHtml(action.requestedBy)}</td>
      <td class="detail">${escapeHtml(action.output || action.error || "")}</td>
      <td class="json-cell">${escapeHtml(action.beforeJson)}</td>
      <td class="json-cell">${escapeHtml(action.afterJson)}</td>
    </tr>
  `);
}

function renderAuditLog(entries) {
  els.auditLogBody.innerHTML = rowsOrEmpty(entries, 6, (entry) => `
    <tr>
      <td>${formatTime(entry.occurredAt)}</td>
      <td>${escapeHtml(entry.actor)}</td>
      <td>${escapeHtml(entry.action)}</td>
      <td>${escapeHtml(entry.entityType)}<br><span class="muted">${escapeHtml(entry.entityId)}</span></td>
      <td><span class="risk ${entry.success ? "low" : "high"}">${entry.success ? "Success" : "Failed"}</span></td>
      <td class="json-cell">${escapeHtml(entry.detailJson)}</td>
    </tr>
  `);
}

function renderSettings(settings, scheduler) {
  els.settingProduct.textContent =
    `${settings.productName} / ${settings.legacyProductName}`;
  els.settingVersion.textContent = settings.productVersion;
  els.settingBindUrl.textContent = settings.bindUrl;
  els.settingRefresh.textContent = `${settings.refreshIntervalMilliseconds} ms`;
  els.settingTelemetry.textContent =
    `${settings.telemetryCollectionIntervalSeconds} sec`;
  els.settingScheduler.textContent = scheduler.enabled ? "On" : "Off";
  els.settingScheduler.className = scheduler.enabled
    ? "state-ok"
    : "state-warning";
  els.settingRetention.textContent =
    `${settings.telemetryRetentionDays} days`;
  els.settingResponseAuth.textContent =
    settings.responseAuthorizationConfigured ? "Configured" : "Locked";
  els.settingResponseAuth.className =
    settings.responseAuthorizationConfigured ? "state-ok" : "state-warning";
  els.settingMigration.textContent = `v${settings.database.latestMigration}`;
  els.ruleSettingsBody.innerHTML = rowsOrEmpty(
    settings.detectionRules || [],
    6,
    (rule) => `
      <tr>
        <td><strong>${escapeHtml(rule.ruleId)}</strong><br>${escapeHtml(rule.name)}</td>
        <td>${escapeHtml(rule.category)}</td>
        <td><span class="risk ${severityClass(rule.severity)}">${escapeHtml(rule.severity)}</span></td>
        <td>${rule.riskWeight}</td>
        <td>${rule.enabled ? "Enabled" : "Disabled"}</td>
        <td class="detail">${escapeHtml(rule.description)}</td>
      </tr>
    `);
  renderScheduler(scheduler);
  renderPolicies(settings.policies);
}

function renderScheduler(scheduler) {
  const tasks = scheduler.tasks || [];
  if (els.schedulerSummary) {
    els.schedulerSummary.textContent = !scheduler.enabled
      ? "Scheduler disabled by configuration."
      : `${escapeLabel(scheduler.health || "healthy")} | ` +
        `${scheduler.runningCount || 0} running, ` +
        `${scheduler.failedCount || 0} failed, ` +
        `${scheduler.dueCount || 0} due, ` +
        `${scheduler.disabledCount || 0} disabled.`;
  }
  els.schedulerBody.innerHTML = rowsOrEmpty(
    tasks,
    7,
    (task) => `
      <tr>
        <td><strong>${escapeHtml(task.displayName)}</strong><br><span class="muted">${escapeHtml(task.taskKey)}</span></td>
        <td>${escapeHtml(task.moduleId || "protection-scheduler")}<br><span class="muted">${escapeHtml(task.category || "")}</span></td>
        <td><span class="risk ${schedulerStateClass(task.dueState || task.lastStatus, task.enabled)}">${escapeHtml(escapeLabel(task.dueState || task.lastStatus))}</span></td>
        <td>${formatDuration(task.intervalSeconds)}</td>
        <td>${formatTime(task.lastCompletedAt || task.lastStartedAt)}</td>
        <td>${formatTime(task.nextRunAt)}</td>
        <td><span class="risk ${task.lastStatus === "failed" ? "high" : task.lastStatus === "running" ? "medium" : "low"}">${escapeHtml(task.lastStatus)}</span><br><span class="muted">${escapeHtml(task.lastMessage || "")}</span></td>
      </tr>
    `);
}

function schedulerStateClass(state, enabled) {
  if (!enabled || state === "disabled") return "medium";
  if (state === "failed") return "high";
  if (state === "running" || state === "due") return "medium";
  return "low";
}

function escapeLabel(value) {
  return (value || "")
    .toString()
    .replace(/[-_]/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
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
  els.ramBar.className = performance.memory.usedPercent >= state.memoryDangerPercent
    ? "danger"
    : performance.memory.usedPercent >= state.memoryWarningPercent
      ? "warning"
      : "";
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

function renderAgents(view, egressRules = [], mcpSummary = {}) {
  const rows = view.agents || [];
  const blockedPaths = new Set((egressRules || []).map(r => (r.executablePath || "").toLowerCase()));

  els.agentsBody.innerHTML = rowsOrEmpty(rows, 10, (agent) => {
    const isEgressBlocked = blockedPaths.has((agent.executablePath || "").toLowerCase());
    return `
    <tr>
      <td><span class="risk ${agent.status === "blocked" ? "critical" : agent.status === "trusted" ? "low" : riskClass(agent.riskScore)}">${escapeHtml(agent.status)}</span></td>
      <td>${escapeHtml(agent.name)}${agent.isRunning ? `<br><span class="muted">Running - PID ${agent.processId ?? "-"}</span>` : `<br><span class="muted">Not running</span>`}</td>
      <td>${escapeHtml(agent.vendor)}</td>
      <td class="path">${escapeHtml(agent.executablePath || "")}</td>
      <td>${formatTime(agent.firstSeen)}</td>
      <td>${formatTime(agent.lastSeen)}</td>
      <td>${agent.networkConnectionCount} flow(s)<br><span class="muted">${agent.distinctRemoteAddressCount} public destination(s)</span></td>
      <td><span class="risk ${riskClass(agent.riskScore)}">${agent.riskScore}</span></td>
      <td class="detail">${escapeHtml(agent.riskReason)}</td>
      <td class="button-row">
        ${agent.canEnforcePath
          ? `${!agent.networkAuthorized
              ? `<button class="mini-button allow" type="button" data-authorize="${escapeHtml(agent.executablePath || "")}">Trust network</button>`
              : ""}
             ${agent.status !== "blocked"
              ? `<button class="mini-button" type="button" data-block-agent="${escapeHtml(agent.executablePath || "")}">Block</button>`
              : `<button class="mini-button allow" type="button" data-unblock-agent="${escapeHtml(agent.executablePath || "")}">Restore</button>`}
             ${!isEgressBlocked
              ? `<button class="mini-button" type="button" data-block-egress="${escapeHtml(agent.executablePath || "")}" data-agent-key="${escapeHtml(agent.agentKey || "")}">Isolate Egress</button>`
              : `<button class="mini-button allow" type="button" data-unblock-egress="${escapeHtml(agent.executablePath || "")}">Restore Egress</button>`}`
          : `<span class="muted">Shared host<br>Review only</span>`}
      </td>
    </tr>`;
  });

  if (els.agentEgressRulesBody) {
    els.agentEgressRulesBody.innerHTML = rowsOrEmpty(egressRules || [], 7, (rule) => `
      <tr>
        <td><code>${escapeHtml(rule.agentKey)}</code></td>
        <td class="path">${escapeHtml(rule.executablePath)}</td>
        <td>${escapeHtml(rule.direction)}</td>
        <td><span class="risk critical">${escapeHtml(rule.action)}</span></td>
        <td>${formatTime(rule.createdAt)}</td>
        <td>${escapeHtml(rule.createdBy)}</td>
        <td><button class="mini-button allow" type="button" data-unblock-egress="${escapeHtml(rule.executablePath)}">Restore Egress</button></td>
      </tr>
    `);
  }

  if (els.mcpTotalCount) els.mcpTotalCount.textContent = mcpSummary?.totalCount ?? 0;
  if (els.mcpBlockedCount) els.mcpBlockedCount.textContent = mcpSummary?.blockedCount ?? 0;
  if (els.mcpWarnedCount) els.mcpWarnedCount.textContent = mcpSummary?.warnedCount ?? 0;
  if (els.mcpToolCount) els.mcpToolCount.textContent = (mcpSummary?.distinctTools || []).length;

  if (els.mcpEventsBody) {
    els.mcpEventsBody.innerHTML = rowsOrEmpty(mcpSummary?.recentEvents || [], 8, (evt) => `
      <tr>
        <td>${formatTime(evt.timestamp)}</td>
        <td><code>${escapeHtml(evt.agentKey)}</code></td>
        <td>${escapeHtml(evt.serverName)}</td>
        <td><strong>${escapeHtml(evt.toolName)}</strong></td>
        <td><span class="risk ${evt.verdict === "Block" ? "critical" : evt.verdict === "Warn" ? "medium" : "low"}">${escapeHtml(evt.verdict)}</span></td>
        <td><span class="risk ${riskClass(evt.riskScore)}">${evt.riskScore}</span></td>
        <td class="detail">${escapeHtml(evt.policyReason)}</td>
        <td class="detail"><code>${escapeHtml(evt.argumentsJson || "")}</code></td>
      </tr>
    `);
  }

  els.agentsBody.querySelectorAll("[data-authorize]").forEach((button) => {
    button.addEventListener("click", () => updateAgentPolicy("/api/actions/authorize-agent", button.dataset.authorize, "authorize"));
  });
  els.agentsBody.querySelectorAll("[data-block-agent]").forEach((button) => {
    button.addEventListener("click", () => updateAgentPolicy("/api/actions/block-agent", button.dataset.blockAgent, "block"));
  });
  els.agentsBody.querySelectorAll("[data-unblock-agent]").forEach((button) => {
    button.addEventListener("click", () => restoreAgent(button.dataset.unblockAgent));
  });
  els.agentsBody.querySelectorAll("[data-block-egress]").forEach((button) => {
    button.addEventListener("click", () => blockAgentEgress(button.dataset.blockEgress, button.dataset.agentKey));
  });
  els.agentsBody.querySelectorAll("[data-unblock-egress]").forEach((button) => {
    button.addEventListener("click", () => unblockAgentEgress(button.dataset.unblockEgress));
  });
  if (els.agentEgressRulesBody) {
    els.agentEgressRulesBody.querySelectorAll("[data-unblock-egress]").forEach((button) => {
      button.addEventListener("click", () => unblockAgentEgress(button.dataset.unblockEgress));
    });
  }
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
  els.startupBody.innerHTML = rowsOrEmpty(entries, 5, (entry) => `
    <tr>
      <td><span class="risk ${riskClass(entry.riskScore)}">${entry.riskScore}</span></td>
      <td>${escapeHtml(entry.name)}</td>
      <td>${escapeHtml(entry.source)}</td>
      <td class="path">${escapeHtml(entry.command)}</td>
      <td><button class="mini-button" type="button"
        data-disable-startup="${escapeHtml(entry.name)}"
        data-startup-source="${escapeHtml(entry.source)}"
        data-startup-command="${escapeHtml(entry.command)}">Disable</button></td>
    </tr>
  `);
  els.startupBody.querySelectorAll("[data-disable-startup]").forEach((button) => {
    button.addEventListener("click", () => disableStartupItem({
      name: button.dataset.disableStartup,
      source: button.dataset.startupSource,
      command: button.dataset.startupCommand
    }));
  });
}

function renderScheduledTasks(tasks) {
  els.scheduledTasksBody.innerHTML = rowsOrEmpty(tasks, 6, (task) => {
    const protectedTask = (task.path || "").toLowerCase().startsWith("\\microsoft\\windows\\");
    const command = [task.command, task.arguments].filter(Boolean).join(" ");
    return `
      <tr>
        <td><span class="risk ${task.enabled ? "medium" : "low"}">${task.enabled ? escapeHtml(task.state) : "Disabled"}</span></td>
        <td>${escapeHtml(task.name)}</td>
        <td class="path">${escapeHtml(task.path)}</td>
        <td class="path">${escapeHtml(command)}</td>
        <td>${escapeHtml(task.trigger || "-")}</td>
        <td>${task.enabled && !protectedTask
          ? `<button class="mini-button" type="button"
              data-disable-task="${escapeHtml(task.name)}"
              data-task-path="${escapeHtml(task.path)}"
              data-task-command="${escapeHtml(command)}">Disable</button>`
          : `<span class="muted">${protectedTask ? "Protected" : "Inactive"}</span>`}
        </td>
      </tr>
    `;
  });
  els.scheduledTasksBody.querySelectorAll("[data-disable-task]").forEach((button) => {
    button.addEventListener("click", () => disableStartupItem({
      name: button.dataset.disableTask,
      source: `ScheduledTask:${button.dataset.taskPath}`,
      command: button.dataset.taskCommand
    }));
  });
}

function unlockResponses(event) {
  event.preventDefault();
  const token = els.operatorToken.value.trim();
  if (!token) {
    return setMessage("Enter a login token.", true);
  }

  login(token);
}

function updateOperatorState() {
  els.operatorState.textContent = state.authenticated
    ? `${state.role} session`
    : "Read-only viewer session";
}

async function refreshSession() {
  try {
    const session = await getJson("/api/auth/session");
    state.authenticated = Boolean(session.authenticated);
    state.role = session.role || "Viewer";
    state.csrfToken = session.csrfToken || "";
    if (state.csrfToken) {
      sessionStorage.setItem("roamsentinel.csrfToken", state.csrfToken);
    } else {
      sessionStorage.removeItem("roamsentinel.csrfToken");
    }
  } catch {
    state.authenticated = false;
    state.role = "Viewer";
    state.csrfToken = "";
  }
  updateOperatorState();
}

async function login(token) {
  const response = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token })
  });
  const result = await response.json();
  els.operatorToken.value = "";
  if (!response.ok) {
    setMessage(result.error || "Login failed.", true);
    return;
  }

  state.authenticated = result.authenticated;
  state.role = result.role;
  state.csrfToken = result.csrfToken;
  sessionStorage.setItem("roamsentinel.csrfToken", result.csrfToken);
  updateOperatorState();
  setMessage(`${result.role} session established.`);
}

async function quarantineFile(event) {
  event.preventDefault();
  const path = new FormData(event.currentTarget).get("path")?.toString().trim();
  if (!path) return setMessage("Enter an absolute file path.", true);
  if (!confirm(`Submit this file to Microsoft Defender for a custom scan and remediation?\n\n${path}`)) return;
  const result = await postJson("/api/actions/quarantine-file", { path });
  setMessage(result.ok ? result.output : result.error, !result.ok);
}

async function disableStartupItem(item) {
  if (!confirm(`Disable this startup item and preserve recovery metadata?\n\n${item.name}\n${item.source}`)) return;
  const result = await postJson("/api/actions/disable-startup", item);
  setMessage(result.ok ? result.output : result.error, !result.ok);
  refreshAll();
}

async function setAlertDisposition(alertId, disposition) {
  const note = prompt("Optional review note:", "") ?? "";
  const url = disposition === "resolve"
    ? "/api/actions/resolve-alert"
    : "/api/actions/false-positive";
  const result = await postJson(url, { alertId, note });
  setMessage(result.ok ? result.output : result.error, !result.ok);
  refreshAll();
}

async function lookupThreatIntel(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const indicator = form.get("indicator")?.toString().trim();
  const indicatorType = form.get("indicatorType")?.toString();
  if (!indicator) {
    els.threatLookupResult.textContent = "Enter an indicator.";
    return;
  }

  els.threatLookupResult.textContent = "Checking configured providers...";
  const result = await postJson("/api/threat-intel/enrich", {
    indicator,
    indicatorType
  });
  if (result.error) {
    els.threatLookupResult.textContent = result.error;
    return;
  }

  els.threatLookupResult.textContent =
    `${result.indicator}: ${result.reputation}, confidence ${result.confidence}. ` +
    `${(result.observations || []).length} provider observation(s).`;
  renderThreatIntel(await getJson("/api/dashboard/threat-intel"));
}

async function scanCodeGate(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const source = form.get("source")?.toString() || "";
  const revision = form.get("revision")?.toString().trim() || "working-copy";
  const importPath = form.get("importPath")?.toString().trim() || "manual-input";
  if (!source.trim()) {
    els.codeGateResult.textContent = "Paste source content before analysis.";
    return;
  }

  els.codeGateResult.textContent = "Analyzing locally...";
  const result = await postJson("/api/modules/codegate/scan", {
    source,
    revision,
    importPath
  });
  if (result.error) {
    els.codeGateResult.textContent = result.error;
    return;
  }

  els.codeGateResult.innerHTML = `
    <strong class="risk ${riskClass(result.riskScore)}">${escapeHtml(result.verdict)}</strong>
    <span>${result.riskScore}/100</span>
    <ul>${(result.findings || []).map(item => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
  `;
  renderComponents(
    await getJson("/api/modules"),
    await getJson("/api/modules/insider-risk"),
    await getJson("/api/v1/codegate/submissions?limit=25"),
    await getJson("/api/v1/codegate/git-pushes?limit=25"),
    await getJson("/api/v1/codegate/offline-bundles?limit=25"),
    await getJson("/api/v1/codegate/rules"));
}

async function exportCodeGateReport(report) {
  const paths = {
    "submissions": "/api/v1/codegate/reports/submissions.csv",
    "git-pushes": "/api/v1/codegate/reports/git-pushes.csv",
    "offline-bundles": "/api/v1/codegate/reports/offline-bundles.csv"
  };
  const names = {
    "submissions": "roamsentinel-codegate-submissions.csv",
    "git-pushes": "roamsentinel-codegate-git-pushes.csv",
    "offline-bundles": "roamsentinel-codegate-offline-bundles.csv"
  };
  const path = paths[report];
  if (!path) return;

  setMessage("Preparing CodeGate audit export...");
  try {
    const url = `${path}?${codeGateReportQuery(report).toString()}`;
    const response = await fetch(url, { cache: "no-store" });
    if (!response.ok) {
      throw new Error(await response.text() || "CodeGate export failed.");
    }

    const objectUrl = URL.createObjectURL(await response.blob());
    const link = document.createElement("a");
    link.href = objectUrl;
    link.download = names[report];
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(objectUrl);
    setMessage(`CodeGate audit export prepared: ${names[report]}.`);
  } catch (error) {
    setMessage(error.message, true);
  }
}

function codeGateReportQuery(report) {
  const query = new URLSearchParams();
  const verdict = els.codeGateVerdictFilter.value;
  const repository = els.codeGateRepositoryFilter.value.trim();
  const actor = els.codeGateActorFilter.value.trim();
  const bundleType = els.codeGateBundleTypeFilter.value;

  query.set("limit", "5000");
  if (report !== "offline-bundles" && verdict) query.set("verdict", verdict);
  if (report === "git-pushes" && repository) query.set("repository", repository);
  if (report === "git-pushes" && actor) query.set("actor", actor);
  if (report === "offline-bundles" && bundleType) query.set("bundleType", bundleType);
  return query;
}

async function loadCodeGateSubmissionDetail(submissionId) {
  if (!submissionId) return;
  els.codeGateDetailPanel.textContent = "Loading CodeGate submission evidence...";
  try {
    const submission = await getJson(`/api/v1/codegate/submissions/${encodeURIComponent(submissionId)}`);
    els.codeGateDetailPanel.classList.remove("muted");
    els.codeGateDetailPanel.innerHTML = `
      <h3>Submission evidence</h3>
      <div class="codegate-detail-grid">
        <div><span>Verdict</span><strong class="risk ${riskClass(submission.riskScore)}">${escapeHtml(submission.verdict)}</strong></div>
        <div><span>Risk</span><strong>${escapeHtml(submission.riskScore)}/100</strong></div>
        <div><span>Actor</span><strong>${escapeHtml(submission.actor)}</strong></div>
        <div><span>Evaluated</span><strong>${formatTime(submission.evaluatedAt)}</strong></div>
        <div><span>Source</span><strong>${escapeHtml(submission.source)}</strong></div>
        <div><span>Revision</span><strong>${escapeHtml(submission.revision)}</strong></div>
        <div><span>Files</span><strong>${escapeHtml(submission.fileCount)}</strong></div>
        <div><span>SHA-256</span><strong>${escapeHtml(submission.contentSha256 || "not recorded")}</strong></div>
      </div>
      <p class="path">${escapeHtml(submission.importPath)}</p>
      <ul class="finding-list">${(submission.findings || []).map(renderCodeGateFinding).join("")}</ul>
    `;
  } catch (error) {
    els.codeGateDetailPanel.classList.add("muted");
    els.codeGateDetailPanel.textContent = error.message;
  }
}

async function loadCodeGateGitPushDetail(auditId) {
  if (!auditId) return;
  els.codeGateDetailPanel.textContent = "Loading CodeGate git push evidence...";
  try {
    const audit = await getJson(`/api/v1/codegate/git-pushes/${encodeURIComponent(auditId)}`);
    els.codeGateDetailPanel.classList.remove("muted");
    els.codeGateDetailPanel.innerHTML = `
      <h3>Git push evidence</h3>
      <div class="codegate-detail-grid">
        <div><span>Verdict</span><strong class="risk ${riskClass(audit.riskScore)}">${escapeHtml(audit.verdict)}</strong></div>
        <div><span>Risk</span><strong>${escapeHtml(audit.riskScore)}/100</strong></div>
        <div><span>Actor</span><strong>${escapeHtml(audit.actor)}</strong></div>
        <div><span>Observed</span><strong>${formatTime(audit.observedAt)}</strong></div>
        <div><span>Repository</span><strong>${escapeHtml(audit.repositoryName)}</strong></div>
        <div><span>Branch</span><strong>${escapeHtml(audit.branch || audit.refName)}</strong></div>
        <div><span>Old revision</span><strong>${escapeHtml(audit.oldRevision || "-")}</strong></div>
        <div><span>New revision</span><strong>${escapeHtml(audit.newRevision || "-")}</strong></div>
      </div>
      <p class="path">${escapeHtml(audit.repositoryPath)}</p>
      <p>Submission: <button class="mini-button" type="button" data-codegate-submission="${escapeHtml(audit.submissionId)}">Open linked submission</button></p>
      <ul class="changed-file-list">${(audit.changedFiles || []).map(file => `<li class="path">${escapeHtml(file)}</li>`).join("")}</ul>
    `;
    els.codeGateDetailPanel.querySelector("[data-codegate-submission]")
      ?.addEventListener("click", () => loadCodeGateSubmissionDetail(audit.submissionId));
  } catch (error) {
    els.codeGateDetailPanel.classList.add("muted");
    els.codeGateDetailPanel.textContent = error.message;
  }
}

function renderCodeGateFinding(finding) {
  return `
    <li>
      <span class="risk ${severityClass(finding.severity)}">${escapeHtml(finding.severity)}</span>
      <strong>${escapeHtml(finding.ruleId)}</strong>
      <span>${escapeHtml(finding.riskScore)}/100</span><br>
      <span class="path">${escapeHtml(finding.filePath)}</span><br>
      <span class="muted">${escapeHtml(finding.explanation)}</span><br>
      <span class="muted">Evidence: ${escapeHtml(finding.evidence)}</span>
    </li>
  `;
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

async function exportBackup() {
  if (!confirm("Export a local RoamSentinel database backup now?")) return;
  setMessage("Preparing backup export...");
  try {
    const response = await fetch("/api/backup/export", {
      method: "POST",
      headers: {
        "X-RoamSentinel-CSRF": state.csrfToken
      }
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || "Backup export failed.");
    }

    const disposition = response.headers.get("Content-Disposition") || "";
    const encodedName = disposition.match(/filename\*=UTF-8''([^;]+)/i)?.[1];
    const plainName = disposition.match(/filename=\"?([^\";]+)\"?/i)?.[1];
    const fileName = encodedName
      ? decodeURIComponent(encodedName)
      : plainName || "RoamSentinel-backup.zip";
    const url = URL.createObjectURL(await response.blob());
    const link = document.createElement("a");
    link.href = url;
    link.download = fileName;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    setMessage(`Backup exported as ${fileName}.`);
    refreshView("auditLog");
  } catch (error) {
    setMessage(error.message, true);
  }
}

async function restoreAgent(path) {
  if (!path) return setMessage("Blocked agent path is unavailable.", true);
  if (!confirm(`Remove RoamSentinel's agent block for this executable?\n\n${path}`)) return;
  const result = await postJson("/api/actions/unblock-agent", { path });
  setMessage(result.ok ? "Agent block restored." : result.error, !result.ok);
  refreshAll();
}

async function blockAgentEgress(path, agentKey) {
  if (!path) return setMessage("Agent path is unavailable.", true);
  if (!confirm(`Isolate outbound and inbound network access via Windows Firewall for ${agentKey || "this agent"}?\n\n${path}`)) return;
  const result = await postJson("/api/actions/block-agent-egress", { path });
  setMessage(result.ok ? (result.output || "Agent egress network isolated.") : result.error, !result.ok);
  refreshAll();
}

async function unblockAgentEgress(path) {
  if (!path) return setMessage("Agent path is unavailable.", true);
  if (!confirm(`Restore network access via Windows Firewall for this agent?\n\n${path}`)) return;
  const result = await postJson("/api/actions/unblock-agent-egress", { path });
  setMessage(result.ok ? (result.output || "Agent network access restored.") : result.error, !result.ok);
  refreshAll();
}

async function restoreIp(ipAddress) {
  if (!ipAddress) return setMessage("Blocked IP is unavailable.", true);
  if (!confirm(`Remove RoamSentinel's Windows Firewall block for ${ipAddress}?`)) return;
  const result = await postJson("/api/actions/unblock-ip", { ipAddress });
  setMessage(result.ok ? `IP block restored for ${ipAddress}.` : result.error, !result.ok);
  refreshAll();
}

function renderDevOps(summary) {
  if (!summary) return;
  const node = summary.node || {};
  const sync = summary.sync || {};
  const claims = summary.activeClaims || [];
  const cycles = summary.cycles || [];
  const reports = summary.recentReports || [];

  if (els.devopsNodeId) els.devopsNodeId.textContent = node.nodeId || "pc-am";
  if (els.devopsNodeRole) els.devopsNodeRole.textContent = `${node.role || "node"} (${node.owner || "local"})`;
  if (els.devopsPushStatus) {
    els.devopsPushStatus.textContent = sync.pushHealthy ? "Healthy" : "Attention";
    els.devopsPushStatus.className = sync.pushHealthy ? "risk low" : "risk critical";
  }
  if (els.devopsLastPush) {
    els.devopsLastPush.textContent = sync.lastPushAt ? `Last: ${formatTime(sync.lastPushAt)}` : "No runs recorded";
  }
  if (els.devopsPullStatus) {
    els.devopsPullStatus.textContent = sync.pullHealthy ? "Healthy" : "Attention";
    els.devopsPullStatus.className = sync.pullHealthy ? "risk low" : "risk critical";
  }
  if (els.devopsLastPull) {
    els.devopsLastPull.textContent = sync.lastPullAt ? `Last: ${formatTime(sync.lastPullAt)}` : "Mirroring GitHub";
  }
  if (els.devopsAppCount) {
    els.devopsAppCount.textContent = sync.totalManagedRepos || 1;
  }

  if (els.devopsPushTableBody) {
    els.devopsPushTableBody.innerHTML = rowsOrEmpty(sync.pushResults || [], 4, (repo) => `
      <tr>
        <td><strong>${escapeHtml(repo.name)}</strong></td>
        <td><span class="risk ${repo.status === "pushed" ? "low" : "critical"}">${escapeHtml(repo.status)}</span></td>
        <td class="detail">${escapeHtml(repo.message || "Pushed clean to GitHub")}</td>
        <td>${repo.exitCode ?? 0}</td>
      </tr>
    `);
  }

  if (els.devopsClaimsBody) {
    els.devopsClaimsBody.innerHTML = rowsOrEmpty(claims, 8, (c) => `
      <tr>
        <td><code>${escapeHtml(c.id)}</code></td>
        <td><strong>${escapeHtml(c.app)}</strong></td>
        <td>${escapeHtml(c.agent)}</td>
        <td class="detail">${escapeHtml(c.task)}</td>
        <td><code>${escapeHtml(c.branch)}</code></td>
        <td class="detail">${(c.scope || []).map(escapeHtml).join("<br>")}</td>
        <td>${formatTime(c.leaseUntil)}</td>
        <td><span class="risk ${c.status === "active" ? "medium" : "low"}">${escapeHtml(c.status)}</span></td>
      </tr>
    `);
  }

  if (els.devopsCyclesBody) {
    els.devopsCyclesBody.innerHTML = rowsOrEmpty(cycles, 6, (cy) => `
      <tr>
        <td><code>${escapeHtml(cy.id)}</code></td>
        <td><strong>${escapeHtml(cy.name)}</strong></td>
        <td><code>${escapeHtml(cy.branch)}</code></td>
        <td>${escapeHtml(cy.startVersion)}</td>
        <td>${escapeHtml(cy.plannedEnd)}</td>
        <td class="detail">${(cy.goals || []).map(escapeHtml).join("<br>")}</td>
      </tr>
    `);
  }

  if (els.devopsReportsList) {
    els.devopsReportsList.innerHTML = reports.length
      ? reports.map((r) => `<li><strong>${escapeHtml(r)}</strong> — <code>C:\\dev\\reports\\daily\\${escapeHtml(r)}\\_global.md</code></li>`).join("")
      : '<li class="muted">No daily reports recorded yet.</li>';
  }
}

async function triggerDevOpsSync(action) {
  if (!confirm(`Run DevHub ${action.toUpperCase()} sync now?`)) return;
  const result = await postJson("/api/v1/devops/sync", { action });
  setMessage(result.ok ? (result.output || `DevHub ${action} sync launched.`) : result.error, !result.ok);
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
    headers: {
      "Content-Type": "application/json",
      "X-RoamSentinel-CSRF": state.csrfToken
    },
    body: JSON.stringify(body)
  });
  const result = await response.json();
  if (response.status === 401 || response.status === 403) {
    if (response.status === 401) {
      state.authenticated = false;
      state.role = "Viewer";
      state.csrfToken = "";
      sessionStorage.removeItem("roamsentinel.csrfToken");
      updateOperatorState();
    }
    setMessage(result.error || "Response authorization failed.", true);
  }
  return result;
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
  if (score >= state.highRiskScore) return "high";
  if (score >= state.mediumRiskScore) return "medium";
  if (score > 0) return "low";
  return "";
}

function activityClass(recommendation, score) {
  if (recommendation === "unused-but-active") return "high";
  if (recommendation === "auto-start-review") return "medium";
  if (recommendation === "review-unused") return "low";
  return riskClass(score);
}

function severityClass(severity) {
  return `sev-${String(severity).toLowerCase()}`;
}

function reputationClass(reputation) {
  const value = String(reputation || "").toLowerCase();
  if (value === "malicious" || value === "blocked") return "high";
  if (value === "suspicious" || value === "high-risk") return "medium";
  return "low";
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

function formatDuration(seconds) {
  const value = Number(seconds || 0);
  if (value >= 86400) return `${Math.round(value / 86400)} day(s)`;
  if (value >= 3600) return `${Math.round(value / 3600)} hour(s)`;
  if (value >= 60) return `${Math.round(value / 60)} min`;
  return `${value} sec`;
}

function formatBytes(value) {
  const bytes = Number(value) || 0;
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#039;");
}
