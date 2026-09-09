/**
 * CYBERSHIELD // Android Mobile Client Controller
 * Native Bridge Hookup, Dual Online/Offline Engine, 60fps Radar,
 * MITRE ATT&CK Matrix, Wireshark Packet Dissector, and AI Triage.
 */

// Configuration & State
let serverBaseUrl = "http://10.0.2.2:8080"; // Android emulator to host loopback default
let isOfflineMode = false;
let ws = null;
let currentAlerts = [];
let activeView = "viewOps";
let latestAlertId = null;
let radarNodes = [];
let activeBeams = [];
let radarAngle = 0;

// Read saved endpoint from Android Native SharedPreferences if available
if (window.AndroidBridge && typeof AndroidBridge.getSavedServerUrl === "function") {
  const saved = AndroidBridge.getSavedServerUrl();
  if (saved && saved.trim()) {
    serverBaseUrl = saved.trim();
  }
}

// Top Elements
const sysClock = document.getElementById("sysClock");
const connStatus = document.getElementById("connStatus");
const diodeLed = document.getElementById("diodeLed");
const diodeStatusText = document.getElementById("diodeStatusText");
const diodeStatusBadge = document.getElementById("diodeStatusBadge");
const toastBox = document.getElementById("toastBox");

// KPI Elements
const metricPps = document.getElementById("metricPps");
const metricMbps = document.getElementById("metricMbps");
const metricPackets = document.getElementById("metricPackets");
const metricUptime = document.getElementById("metricUptime");
const metricFlows = document.getElementById("metricFlows");
const metricLatency = document.getElementById("metricLatency");
const metricAlerts = document.getElementById("metricAlerts");
const metricSeveritySummary = document.getElementById("metricSeveritySummary");

// Radar & Stream Elements
const btnToggleGen = document.getElementById("btnToggleGen");
const genToggleText = document.getElementById("genToggleText");
const alertsTableBody = document.getElementById("alertsTableBody");

// Tab Navigation
const tabButtons = document.querySelectorAll(".nav-tab-btn");
const tabViews = document.querySelectorAll(".tab-view");
const mitreHitBadge = document.getElementById("mitreHitBadge");

// Dissector Elements
const packetTreeContainer = document.getElementById("packetTreeContainer");
const hexDumpContainer = document.getElementById("hexDumpContainer");

// Triage Elements
const triageTitle = document.getElementById("triageTitle");
const triageThreatClass = document.getElementById("triageThreatClass");
const triageSevConf = document.getElementById("triageSevConf");
const triageMitreId = document.getElementById("triageMitreId");
const triageActor = document.getElementById("triageActor");
const triageSummary = document.getElementById("triageSummary");
const triageBlastRadius = document.getElementById("triageBlastRadius");
const triagePlaybook = document.getElementById("triagePlaybook");

// Rules Elements
const ruleIptables = document.getElementById("ruleIptables");
const ruleNftables = document.getElementById("ruleNftables");
const ruleSuricata = document.getElementById("ruleSuricata");
const ruleSnort = document.getElementById("ruleSnort");
const rulePfsense = document.getElementById("rulePfsense");

// Terminal Elements
const termHistory = document.getElementById("termHistory");
const termInput = document.getElementById("termInput");
const btnTermSend = document.getElementById("btnTermSend");

// Modal Elements
const settingsModal = document.getElementById("settingsModal");
const btnCloseSettings = document.getElementById("btnCloseSettings");
const btnPresetEmulator = document.getElementById("btnPresetEmulator");
const btnPresetCloudflare = document.getElementById("btnPresetCloudflare");
const btnPresetOffline = document.getElementById("btnPresetOffline");
const inputCustomServer = document.getElementById("inputCustomServer");
const btnSaveServer = document.getElementById("btnSaveServer");

// -------------------------------------------------------------
// System Clock
// -------------------------------------------------------------
function updateClock() {
  const now = new Date();
  if (sysClock) {
    sysClock.textContent = now.toISOString().substring(11, 16) + " UTC";
  }
}
setInterval(updateClock, 1000);
updateClock();

// -------------------------------------------------------------
// Toast & Haptic Feedback Bridge
// -------------------------------------------------------------
function showToast(message, icon = "⚡", haptic = null) {
  if (window.AndroidBridge && typeof AndroidBridge.showToast === "function") {
    AndroidBridge.showToast(`${icon} ${message}`);
  }
  if (haptic && window.AndroidBridge && typeof AndroidBridge.triggerHaptic === "function") {
    AndroidBridge.triggerHaptic(haptic);
  }

  if (!toastBox) return;
  toastBox.innerHTML = `<span>${icon}</span><span>${message}</span>`;
  toastBox.style.display = "flex";
  toastBox.style.opacity = "1";

  setTimeout(() => {
    toastBox.style.transition = "opacity 0.3s";
    toastBox.style.opacity = "0";
    setTimeout(() => { toastBox.style.display = "none"; }, 300);
  }, 2500);
}

// -------------------------------------------------------------
// Workspace Tab Switching
// -------------------------------------------------------------
function switchView(viewId) {
  activeView = viewId;
  tabButtons.forEach(btn => {
    if (btn.dataset.view === viewId) btn.classList.add("active");
    else btn.classList.remove("active");
  });

  tabViews.forEach(v => {
    if (v.id === viewId) v.classList.add("active");
    else v.classList.remove("active");
  });

  if (viewId === "viewMitre") loadMitreMatrix();
  else if (viewId === "viewDissect") loadPacketDissection();
  else if (viewId === "viewTriage") loadTriageReport(latestAlertId);
  else if (viewId === "viewRules") loadMitigationRules(latestAlertId);
}

tabButtons.forEach(btn => {
  btn.addEventListener("click", () => switchView(btn.dataset.view));
});

// -------------------------------------------------------------
// Connection & Telemetry Management (Online / Offline Fallback)
// -------------------------------------------------------------
function setServerEndpoint(url, isOffline = false) {
  isOfflineMode = isOffline;
  serverBaseUrl = url.replace(/\/$/, "");

  if (window.AndroidBridge && typeof AndroidBridge.saveServerUrl === "function") {
    AndroidBridge.saveServerUrl(serverBaseUrl);
  }

  if (isOfflineMode) {
    if (connStatus) {
      connStatus.textContent = "AIR-GAP DEMO";
      connStatus.className = "status-pill pill-online";
    }
    if (diodeStatusText) diodeStatusText.textContent = "STANDALONE SENSOR";
    startOfflineSimulation();
    showToast("Switched to Standalone Air-Gap Simulation Mode", "🛡️");
  } else {
    initWebSocket();
    showToast(`Connecting to ${serverBaseUrl}...`, "🔗");
  }
}

function initWebSocket() {
  if (isOfflineMode) return;
  if (ws) {
    try { ws.close(); } catch (e) {}
  }

  const wsProto = serverBaseUrl.startsWith("https") ? "wss:" : "ws:";
  const hostPart = serverBaseUrl.replace(/^https?:\/\//, "");
  const wsUrl = `${wsProto}//${hostPart}/ws/live`;

  try {
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      connStatus.textContent = "LIVE ENCLAVE";
      connStatus.className = "status-pill pill-online";
      if (diodeStatusText) diodeStatusText.textContent = "OPTICAL RX ONLY";
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        handleTelemetryUpdate(data);
      } catch (e) {}
    };

    ws.onclose = () => {
      connStatus.textContent = "OFFLINE (STANDBY)";
      connStatus.className = "status-pill pill-offline";
      // Auto-engage offline simulation if server connection fails
      startOfflineSimulation();
    };

    ws.onerror = () => {
      ws.close();
    };
  } catch (err) {
    startOfflineSimulation();
  }
}

// -------------------------------------------------------------
// Offline Simulation Engine (Enables 100% Zero-Server Android Testing)
// -------------------------------------------------------------
let offlineTimer = null;
let simPackets = 142050;
let simUptime = 12;

function startOfflineSimulation() {
  if (offlineTimer) return;
  if (connStatus) {
    connStatus.textContent = "AIR-GAP DEMO";
    connStatus.className = "status-pill pill-online";
  }

  offlineTimer = setInterval(() => {
    simPackets += Math.floor(Math.random() * 2400) + 1200;
    simUptime += 1;

    const mockTelemetry = {
      sustained_pps: Math.floor(Math.random() * 8000) + 28000,
      instant_mbps: (Math.random() * 4.2 + 18.5).toFixed(1),
      total_packets: simPackets,
      uptime_sec: simUptime,
      active_flows: Math.floor(Math.random() * 40) + 120,
      eval_latency_ms: (Math.random() * 0.3 + 0.1).toFixed(2),
      alerts_count: currentAlerts.length || 3,
      severity_breakdown: {
        CRITICAL: currentAlerts.filter(a => a.severity === "CRITICAL").length || 1,
        HIGH: currentAlerts.filter(a => a.severity === "HIGH").length || 1,
        MEDIUM: 1
      },
      recent_alerts: currentAlerts.length > 0 ? currentAlerts : [
        {
          alert_id: "SIM-SYN-01",
          timestamp: Date.now() / 1000 - 4,
          threat_class: "VOLUMETRIC_SYN_FLOOD",
          severity: "CRITICAL",
          confidence_score: 0.98,
          src_ip: "172.16.42.19",
          dst_ip: "192.168.1.1",
          dst_port: 80
        },
        {
          alert_id: "SIM-C2-02",
          timestamp: Date.now() / 1000 - 12,
          threat_class: "BOTNET_C2_BEACONING",
          severity: "HIGH",
          confidence_score: 0.94,
          src_ip: "192.168.1.105",
          dst_ip: "203.0.113.88",
          dst_port: 443
        }
      ]
    };

    handleTelemetryUpdate(mockTelemetry);
  }, 1000);
}

// -------------------------------------------------------------
// Telemetry UI Updates
// -------------------------------------------------------------
function handleTelemetryUpdate(data) {
  if (metricPps) metricPps.textContent = (data.sustained_pps || 0).toLocaleString();
  if (metricMbps) metricMbps.textContent = `${data.instant_mbps || 0.0} Mbps // 16 Shards`;
  if (metricPackets) metricPackets.textContent = (data.total_packets || 0).toLocaleString();
  if (metricUptime) metricUptime.textContent = `Uptime: ${Math.round(data.uptime_sec || 0)}s`;
  if (metricFlows) metricFlows.textContent = `${data.active_flows || 0} Active Flows`;
  if (metricLatency) metricLatency.textContent = `${data.eval_latency_ms || 0.0} ms`;

  const alertsCount = data.alerts_count || 0;
  if (metricAlerts) metricAlerts.textContent = alertsCount.toLocaleString();

  const sev = data.severity_breakdown || {};
  if (metricSeveritySummary) {
    metricSeveritySummary.textContent = `${sev.CRITICAL || 0} Crit / ${sev.HIGH || 0} High`;
  }

  if (diodeLed) {
    if ((sev.CRITICAL || 0) > 0) {
      diodeLed.style.background = "#f87171";
      diodeLed.style.boxShadow = "0 0 10px #f87171";
    } else {
      diodeLed.style.background = "#34d399";
      diodeLed.style.boxShadow = "0 0 6px #34d399";
    }
  }

  if (data.recent_alerts && data.recent_alerts.length > 0) {
    currentAlerts = data.recent_alerts;
    latestAlertId = currentAlerts[0].alert_id;
    renderAlertsTable();
  }

  // Trigger occasional radar beam
  if (Math.random() < 0.4) {
    triggerRadarBeam("172.16.x.x", "192.168.1.1", "#f87171");
  }
}

function renderAlertsTable() {
  if (!alertsTableBody) return;

  alertsTableBody.innerHTML = currentAlerts.map(a => {
    const timeStr = new Date(a.timestamp * 1000).toTimeString().substring(0, 8);
    const targetFlow = `${a.src_ip} &rarr; ${a.dst_ip}${a.dst_port ? ":" + a.dst_port : ""}`;
    const confPct = Math.round((a.confidence_score || 0.95) * 100);

    let sevClass = "pill-medium";
    if (a.severity === "CRITICAL") sevClass = "pill-critical";
    else if (a.severity === "HIGH") sevClass = "pill-high";

    return `
      <tr>
        <td style="font-family: var(--font-mono); color: var(--text-dim);">${timeStr}</td>
        <td><span class="sev-pill ${sevClass}">${a.severity}</span></td>
        <td style="font-weight: 700; color: #fff;">${a.threat_class}</td>
        <td style="font-family: var(--font-mono); font-size: 0.68rem; color: #38bdf8;">${targetFlow}</td>
        <td style="font-family: var(--font-mono); font-weight: 700;">${confPct}%</td>
        <td>
          <div style="display: flex; gap: 4px;">
            <button class="btn-table-action" onclick="triageAlert('${a.alert_id}')">Triage</button>
            <button class="btn-table-action" onclick="dissectAlert('${a.alert_id}')">Dissect</button>
          </div>
        </td>
      </tr>
    `;
  }).join("");
}

window.triageAlert = function(alertId) {
  latestAlertId = alertId;
  switchView("viewTriage");
  loadTriageReport(alertId);
};

window.dissectAlert = function(alertId) {
  latestAlertId = alertId;
  switchView("viewDissect");
  loadPacketDissection(alertId);
};

// -------------------------------------------------------------
// Interactive Attack Injection Actions
// -------------------------------------------------------------
async function triggerAttack(type, payload = {}) {
  showToast(`Injecting ${type}...`, "🚨", "CRITICAL");

  if (isOfflineMode || !ws || ws.readyState !== WebSocket.OPEN) {
    // Offline simulation injection
    const newAlert = {
      alert_id: `SIM-${Date.now().toString().slice(-4)}`,
      timestamp: Date.now() / 1000,
      threat_class: type === "SYN_FLOOD" ? "VOLUMETRIC_SYN_FLOOD" :
                    type === "C2_BEACON" ? "BOTNET_C2_BEACONING" :
                    type === "PORT_SCAN" ? "RECONNAISSANCE_SCAN" :
                    type === "DGA" ? "DGA_OR_DNS_TUNNEL" : "SUSPICIOUS_JA4_TLS",
      severity: (type === "SYN_FLOOD" || type === "JA4") ? "CRITICAL" : "HIGH",
      confidence_score: 0.98,
      src_ip: payload.target_ip ? "172.16.88.2" : "192.168.1.105",
      dst_ip: payload.target_ip || "203.0.113.88",
      dst_port: payload.port || 443
    };
    currentAlerts.unshift(newAlert);
    renderAlertsTable();
    showToast(`Simulation alert registered: ${newAlert.threat_class}`, "✅", "HIGH");
    return;
  }

  try {
    const res = await fetch(`${serverBaseUrl}/api/inject`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type, ...payload })
    });
    const result = await res.json();
    showToast(result.message || "Vector injected", "✅");
  } catch (err) {
    showToast("Backend call failed, local alert created", "⚠️");
  }
}

document.getElementById("btnInjectSyn")?.addEventListener("click", () => {
  triggerAttack("SYN_FLOOD", { target_ip: "192.168.1.1", port: 80 });
});
document.getElementById("btnInjectBeacon")?.addEventListener("click", () => {
  triggerAttack("C2_BEACON", { bot_ip: "192.168.1.105", c2_ip: "203.0.113.88" });
});
document.getElementById("btnInjectScan")?.addEventListener("click", () => {
  triggerAttack("PORT_SCAN", { scanner_ip: "192.168.1.199", target_ip: "10.0.0.5" });
});
document.getElementById("btnInjectDga")?.addEventListener("click", () => {
  triggerAttack("DGA", { client_ip: "192.168.1.45" });
});
document.getElementById("btnInjectJa4")?.addEventListener("click", () => {
  triggerAttack("JA4", { client_ip: "192.168.1.77", c2_ip: "185.220.101.5" });
});
document.getElementById("btnReplayPcap")?.addEventListener("click", () => {
  showToast("Replaying multi-threat PCAP...", "📼");
});

document.getElementById("btnClearAlerts")?.addEventListener("click", () => {
  currentAlerts = [];
  renderAlertsTable();
  showToast("Alert feed cleared", "🗑️");
});

// -------------------------------------------------------------
// MITRE ATT&CK Matrix View
// -------------------------------------------------------------
async function loadMitreMatrix() {
  const grid = document.getElementById("mitreMatrixGrid");
  if (!grid) return;

  grid.innerHTML = `<div style="padding: 20px; color: var(--text-dim);">Loading MITRE Matrix...</div>`;

  try {
    const res = await fetch(`${serverBaseUrl}/api/mitre/matrix`);
    const data = await res.json();
    renderMitreGrid(data);
  } catch (e) {
    // Render local fallback matrix
    renderMitreGrid(getFallbackMitreData());
  }
}

function renderMitreGrid(data) {
  const grid = document.getElementById("mitreMatrixGrid");
  if (!grid) return;

  if (mitreHitBadge) {
    const activeTotal = data.active_techniques ? data.active_techniques.length : 2;
    mitreHitBadge.textContent = `${activeTotal} Active`;
  }

  grid.innerHTML = (data.tactics || []).map(t => `
    <div class="mitre-tactic-col">
      <div class="mitre-tactic-title">${t.name}</div>
      ${(t.techniques || []).map(tech => `
        <div class="mitre-tech-card ${tech.active ? 'active-tech' : ''}">
          <div class="tech-id">${tech.id}</div>
          <div class="tech-name">${tech.name}</div>
        </div>
      `).join("")}
    </div>
  `).join("");
}

function getFallbackMitreData() {
  return {
    tactics: [
      { name: "Reconnaissance", techniques: [{ id: "T1595", name: "Active Scanning", active: true }] },
      { name: "Initial Access", techniques: [{ id: "T1190", name: "Exploit Public App", active: false }] },
      { name: "Defense Evasion", techniques: [{ id: "T1573.002", name: "Encrypted Channel", active: true }] },
      { name: "Discovery", techniques: [{ id: "T1046", name: "Port Scanning", active: true }] },
      { name: "Command & Control", techniques: [{ id: "T1071.001", name: "Web Protocols", active: true }, { id: "T1568.002", name: "DGA Domain", active: true }] },
      { name: "Impact", techniques: [{ id: "T1498.001", name: "Direct SYN Flood", active: true }] }
    ]
  };
}

document.getElementById("btnRefreshMitre")?.addEventListener("click", loadMitreMatrix);

// -------------------------------------------------------------
// Packet Dissector View
// -------------------------------------------------------------
async function loadPacketDissection() {
  if (!packetTreeContainer || !hexDumpContainer) return;

  try {
    const res = await fetch(`${serverBaseUrl}/api/dissect/packet`);
    const data = await res.json();
    const pkt = data.packets && data.packets.length > 0 ? data.packets[0] : null;
    if (pkt) {
      packetTreeContainer.innerHTML = (pkt.layers || []).map((l, i) => `
        <div class="tree-layer-box">
          <div class="tree-layer-head">▶ [Layer ${i+1}] ${l.name}</div>
          <div style="padding: 4px 8px; font-family: var(--font-mono); font-size: 0.68rem; color: #94a3b8;">${l.info}</div>
        </div>
      `).join("");
      hexDumpContainer.textContent = pkt.hex_dump;
      return;
    }
  } catch (e) {}

  // Local fallback
  packetTreeContainer.innerHTML = `
    <div class="tree-layer-box">
      <div class="tree-layer-head">▶ [Layer 1] Frame 1 (512 bytes on wire)</div>
    </div>
    <div class="tree-layer-box">
      <div class="tree-layer-head">▶ [Layer 2] Ethernet II: 00:0c:29:8b:42:11 &rarr; 00:50:56:c0:00:08</div>
    </div>
    <div class="tree-layer-box">
      <div class="tree-layer-head">▶ [Layer 3] IPv4: 192.168.1.77 &rarr; 185.220.101.5</div>
    </div>
    <div class="tree-layer-box">
      <div class="tree-layer-head">▶ [Layer 4] TLSv1.3 ClientHello (JA4: t13d1516h2_8daaf6152771)</div>
    </div>
  `;
  hexDumpContainer.textContent =
    "0000   00 50 56 c0 00 08 00 0c 29 8b 42 11 08 00 45 00  .PV.....).B...E.\n" +
    "0010   01 f2 3a 4f 40 00 40 06 8d 2e c0 a8 01 4d b9 dc  ..:O@.@......M..\n" +
    "0020   65 05 c0 00 01 bb 27 0f 00 00 00 00 00 00 80 18  e.....'.........\n" +
    "0030   fa f0 00 00 00 00 01 01 08 0a 00 00 16 03 01 01  ................";
}
document.getElementById("btnRefreshDissect")?.addEventListener("click", loadPacketDissection);

// -------------------------------------------------------------
// AI Incident Triage View
// -------------------------------------------------------------
async function loadTriageReport(alertId = null) {
  if (!triageSummary) return;

  try {
    const res = await fetch(`${serverBaseUrl}/api/ai/triage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alert_id: alertId })
    });
    const data = await res.json();
    if (data.status === "ok" && data.triage) {
      renderTriageData(data.triage);
      return;
    }
  } catch (e) {}

  // Local fallback triage report
  renderTriageData({
    incident_id: alertId || "INC-2026-084",
    threat_class: "BOTNET_C2_BEACONING",
    severity: "HIGH",
    confidence_score: 0.95,
    mitre_technique_id: "T1071.001",
    adversary_profile: { actor_attribution: "Cobalt Strike Malleable C2" },
    executive_summary: "Automated sensor evaluation detected high-precision periodic callback heartbeats (CV < 0.15) originating from host 192.168.1.105 destined for external C2 server 203.0.113.88.",
    blast_radius_analysis: "Infected endpoint actively communicating with adversary controller. Risk of credential harvesting and lateral movement to internal subnets.",
    containment_playbook: [
      { step: 1, priority: "P0", action: "Quarantine infected endpoint", command: "iptables -I FORWARD -s 192.168.1.105 -j DROP" },
      { step: 2, priority: "P1", action: "Block external C2 destination", command: "firewall-cmd --add-rich-rule='rule family=ipv4 destination address=203.0.113.88 drop'" }
    ]
  });
}

function renderTriageData(t) {
  if (triageTitle) triageTitle.textContent = `INCIDENT TRIAGE // ${t.incident_id || 'INC-001'}`;
  if (triageThreatClass) triageThreatClass.textContent = t.threat_class || 'UNKNOWN';
  if (triageSevConf) triageSevConf.textContent = `${t.severity} (${Math.round((t.confidence_score || 0.95) * 100)}%)`;
  if (triageMitreId) triageMitreId.textContent = t.mitre_technique_id || 'T1071.001';
  if (triageActor) triageActor.textContent = t.adversary_profile ? t.adversary_profile.actor_attribution : 'Botnet Cluster';
  if (triageSummary) triageSummary.textContent = t.executive_summary;
  if (triageBlastRadius) triageBlastRadius.textContent = t.blast_radius_analysis;

  if (triagePlaybook && t.containment_playbook) {
    triagePlaybook.innerHTML = t.containment_playbook.map(s => `
      <div style="background: var(--bg-surface-elevated); border: 1px solid var(--border-subtle); padding: 6px; border-radius: 4px;">
        <div style="font-weight: 700; font-size: 0.72rem; color: var(--accent-amber);">[${s.priority}] Step ${s.step}: ${s.action}</div>
        <pre style="font-family: var(--font-mono); font-size: 0.65rem; color: var(--accent-blue); margin-top: 4px; overflow-x: auto;">${s.command}</pre>
      </div>
    `).join("");
  }
}

document.getElementById("btnReTriageLatest")?.addEventListener("click", () => loadTriageReport());

// -------------------------------------------------------------
// Mitigation Rules View
// -------------------------------------------------------------
async function loadMitigationRules(alertId = null) {
  try {
    const res = await fetch(`${serverBaseUrl}/api/ai/synthesize_rule`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alert_id: alertId })
    });
    const data = await res.json();
    if (data.status === "ok" && data.rules) {
      if (ruleIptables) ruleIptables.textContent = data.rules.iptables;
      if (ruleNftables) ruleNftables.textContent = data.rules.nftables;
      if (ruleSuricata) ruleSuricata.textContent = data.rules.suricata;
      if (ruleSnort) ruleSnort.textContent = data.rules.snort;
      if (rulePfsense) rulePfsense.textContent = data.rules.pfsense;
      return;
    }
  } catch (e) {}

  if (ruleIptables) ruleIptables.textContent = "iptables -A INPUT -p tcp --dport 80 -m hashlimit --hashlimit-above 50/sec -j DROP";
  if (ruleNftables) ruleNftables.textContent = "table inet filter { chain input { tcp dport 80 drop } }";
  if (ruleSuricata) ruleSuricata.textContent = 'drop tcp 192.168.1.105 any -> 203.0.113.88 443 (msg:"C2 Beacon"; sid:2000001; rev:1;)';
  if (ruleSnort) ruleSnort.textContent = 'drop ip 192.168.1.105 any <> 203.0.113.88 any (msg:"Host C2"; sid:3000001; rev:1;)';
  if (rulePfsense) rulePfsense.textContent = '<rule><type>block</type><source><address>192.168.1.105</address></source></rule>';
}

window.copyRule = function(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;
  const text = el.textContent || el.innerText;
  navigator.clipboard.writeText(text).then(() => {
    showToast("Rule copied to clipboard", "📋", "HIGH");
  }).catch(() => {
    showToast("Rule copied", "📋");
  });
};

// -------------------------------------------------------------
// Security Analyst Terminal Console
// -------------------------------------------------------------
async function executeAnalystCommand(query) {
  if (!query || !query.trim()) return;
  const q = query.trim();

  const userEntry = document.createElement("div");
  userEntry.className = "term-entry-user";
  userEntry.textContent = `analyst@soc:~$ ${q}`;
  termHistory.appendChild(userEntry);

  if (termInput) termInput.value = "";
  termHistory.scrollTop = termHistory.scrollHeight;

  try {
    const res = await fetch(`${serverBaseUrl}/api/ai/query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: q })
    });
    const data = await res.json();
    appendAiTerminalResponse(data.response);
  } catch (err) {
    // Local deterministic response
    if (q.includes("status")) {
      appendAiTerminalResponse("CYBERSHIELD SENSOR STATUS: Active 16 Shards. Air-Gapped Optical Diode Monitor Online.");
    } else if (q.includes("mitre")) {
      appendAiTerminalResponse("MITRE STATUS: Techniques T1498.001, T1071.001, and T1046 active.");
    } else if (q.includes("isolate")) {
      appendAiTerminalResponse("ISOLATION PLAYBOOK:\niptables -I FORWARD -s 192.168.1.105 -j DROP\narp -s 192.168.1.105 00:00:00:00:00:00");
    } else if (q.includes("ja4")) {
      appendAiTerminalResponse("JA4 THREAT DB: Cobalt Strike matched t13d1516h2_8daaf6152771.");
    } else {
      appendAiTerminalResponse(`Command executed: "${q}". Sensor core operational.`);
    }
  }
}

function appendAiTerminalResponse(text) {
  const aiEntry = document.createElement("div");
  aiEntry.className = "term-entry-ai";
  aiEntry.textContent = text;
  termHistory.appendChild(aiEntry);
  termHistory.scrollTop = termHistory.scrollHeight;
}

termInput?.addEventListener("keydown", (e) => {
  if (e.key === "Enter") executeAnalystCommand(termInput.value);
});
btnTermSend?.addEventListener("click", () => executeAnalystCommand(termInput.value));

document.getElementById("btnQueryStatus")?.addEventListener("click", () => executeAnalystCommand("status"));
document.getElementById("btnQueryMitre")?.addEventListener("click", () => executeAnalystCommand("mitre"));
document.getElementById("btnQueryIsolate")?.addEventListener("click", () => executeAnalystCommand("isolate host 192.168.1.105"));
document.getElementById("btnQueryJa4")?.addEventListener("click", () => executeAnalystCommand("ja4 analysis"));

// -------------------------------------------------------------
// Endpoint Settings Modal
// -------------------------------------------------------------
diodeStatusBadge?.addEventListener("click", () => {
  if (inputCustomServer) inputCustomServer.value = serverBaseUrl;
  if (settingsModal) settingsModal.classList.add("open");
});

btnCloseSettings?.addEventListener("click", () => {
  if (settingsModal) settingsModal.classList.remove("open");
});

btnPresetEmulator?.addEventListener("click", () => {
  setServerEndpoint("http://10.0.2.2:8080", false);
  if (settingsModal) settingsModal.classList.remove("open");
});

btnPresetCloudflare?.addEventListener("click", () => {
  setServerEndpoint("https://lower-watts-new-mistakes.trycloudflare.com", false);
  if (settingsModal) settingsModal.classList.remove("open");
});

btnPresetOffline?.addEventListener("click", () => {
  setServerEndpoint("http://localhost:8080", true);
  if (settingsModal) settingsModal.classList.remove("open");
});

btnSaveServer?.addEventListener("click", () => {
  const custom = inputCustomServer?.value?.trim();
  if (custom) {
    setServerEndpoint(custom, false);
  }
  if (settingsModal) settingsModal.classList.remove("open");
});

// -------------------------------------------------------------
// Canvas Radar Visualizer
// -------------------------------------------------------------
const canvas = document.getElementById("radarCanvas");
const ctx = canvas ? canvas.getContext("2d") : null;

function resizeCanvas() {
  if (!canvas || !canvas.parentElement) return;
  const rect = canvas.parentElement.getBoundingClientRect();
  canvas.width = rect.width;
  canvas.height = rect.height;
}
window.addEventListener("resize", resizeCanvas);
if (canvas) resizeCanvas();

function initRadarNodes() {
  if (!canvas) return;
  const cx = canvas.width / 2;
  const cy = canvas.height / 2;
  const radius = Math.min(cx, cy) * 0.75;

  radarNodes = [
    { label: "Gateway", x: cx, y: cy, type: "internal", color: "#34d399" },
    { label: "SYN Flood", angle: 0.2, dist: radius * 0.9, color: "#f87171" },
    { label: "C2 Beacon", angle: 1.8, dist: radius * 0.85, color: "#c084fc" },
    { label: "Port Scan", angle: 3.2, dist: radius * 0.75, color: "#fbbf24" },
    { label: "JA4 TLS", angle: 4.5, dist: radius * 0.88, color: "#f87171" }
  ];
}
if (canvas) initRadarNodes();

function triggerRadarBeam(src, dst, color) {
  if (!canvas) return;
  const cx = canvas.width / 2;
  const cy = canvas.height / 2;
  const angle = Math.random() * Math.PI * 2;
  const dist = (Math.min(cx, cy) * 0.75) * (0.6 + Math.random() * 0.35);

  activeBeams.push({
    startX: cx + Math.cos(angle) * dist,
    startY: cy + Math.sin(angle) * dist,
    targetX: cx,
    targetY: cy,
    progress: 0,
    speed: 0.05 + Math.random() * 0.04,
    color: color
  });
}

function drawRadar() {
  if (!canvas || !ctx) return;
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  const cx = canvas.width / 2;
  const cy = canvas.height / 2;
  const maxRadius = Math.min(cx, cy) * 0.85;

  // Circles
  for (let r = 0.25; r <= 1.0; r += 0.25) {
    ctx.beginPath();
    ctx.arc(cx, cy, maxRadius * r, 0, Math.PI * 2);
    ctx.strokeStyle = "rgba(56, 189, 248, 0.15)";
    ctx.stroke();
  }

  // Sweep
  radarAngle += 0.03;
  if (radarAngle >= Math.PI * 2) radarAngle = 0;

  ctx.beginPath();
  ctx.moveTo(cx, cy);
  ctx.lineTo(cx + Math.cos(radarAngle) * maxRadius, cy + Math.sin(radarAngle) * maxRadius);
  ctx.strokeStyle = "rgba(56, 189, 248, 0.6)";
  ctx.stroke();

  // Center node
  ctx.beginPath();
  ctx.arc(cx, cy, 6, 0, Math.PI * 2);
  ctx.fillStyle = "#34d399";
  ctx.fill();

  // Threat Nodes
  radarNodes.forEach(node => {
    if (node.type === "internal") return;
    const nx = cx + Math.cos(node.angle) * node.dist;
    const ny = cy + Math.sin(node.angle) * node.dist;
    ctx.beginPath();
    ctx.arc(nx, ny, 4, 0, Math.PI * 2);
    ctx.fillStyle = node.color;
    ctx.fill();
  });

  // Beams
  for (let i = activeBeams.length - 1; i >= 0; i--) {
    const beam = activeBeams[i];
    beam.progress += beam.speed;
    const curX = beam.startX + (beam.targetX - beam.startX) * beam.progress;
    const curY = beam.startY + (beam.targetY - beam.startY) * beam.progress;

    ctx.beginPath();
    ctx.arc(curX, curY, 3, 0, Math.PI * 2);
    ctx.fillStyle = beam.color;
    ctx.fill();

    if (beam.progress >= 1.0) activeBeams.splice(i, 1);
  }

  requestAnimationFrame(drawRadar);
}

if (canvas) requestAnimationFrame(drawRadar);

// Initial connection attempt
initWebSocket();
