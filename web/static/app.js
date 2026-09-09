/**
 * CYBERSHIELD // Enterprise Security Operations & Autonomous Threat Enclave
 * Client Controller: Live WebSocket Telemetry, 60fps Radar, Tabbed Multi-View Workspace,
 * MITRE ATT&CK Matrix, Wireshark Protocol Dissector, AI Incident Triage, Rule Synthesizer,
 * and Tactical Analyst Terminal.
 */

// Global State
let ws = null;
let currentAlerts = [];
let activeFilter = "ALL";
let activeView = "viewOps";
let latestAlertId = null;
let radarNodes = [];
let activeBeams = [];
let radarAngle = 0;

// Top Elements
const sysClock = document.getElementById("sysClock");
const connStatus = document.getElementById("connStatus");
const diodeLed = document.getElementById("diodeLed");
const toastBox = document.getElementById("toastBox");

// KPI Metrics
const metricPps = document.getElementById("metricPps");
const metricMbps = document.getElementById("metricMbps");
const metricPackets = document.getElementById("metricPackets");
const metricUptime = document.getElementById("metricUptime");
const metricFlows = document.getElementById("metricFlows");
const metricLatency = document.getElementById("metricLatency");
const metricAlerts = document.getElementById("metricAlerts");
const metricSeveritySummary = document.getElementById("metricSeveritySummary");

// Radar & Stream Controls
const rateSlider = document.getElementById("rateSlider");
const rateValueDisplay = document.getElementById("rateValueDisplay");
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

// -------------------------------------------------------------
// System Clock
// -------------------------------------------------------------
function updateClock() {
  const now = new Date();
  if (sysClock) {
    sysClock.textContent = now.toISOString().substring(11, 19) + " UTC";
  }
}
setInterval(updateClock, 1000);
updateClock();

// -------------------------------------------------------------
// Toast Notifications
// -------------------------------------------------------------
function showToast(message, icon = "⚡") {
  if (!toastBox) return;
  toastBox.innerHTML = `<span>${icon}</span><span>${message}</span>`;
  toastBox.style.display = "flex";
  toastBox.style.opacity = "1";
  toastBox.style.transform = "translateY(0)";

  setTimeout(() => {
    toastBox.style.transition = "opacity 0.4s, transform 0.4s";
    toastBox.style.opacity = "0";
    toastBox.style.transform = "translateY(10px)";
    setTimeout(() => {
      toastBox.style.display = "none";
    }, 400);
  }, 3000);
}

// -------------------------------------------------------------
// Workspace Tab Switching
// -------------------------------------------------------------
function switchView(viewId) {
  activeView = viewId;
  tabButtons.forEach(btn => {
    if (btn.dataset.view === viewId) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  });

  tabViews.forEach(v => {
    if (v.id === viewId) {
      v.classList.add("active");
    } else {
      v.classList.remove("active");
    }
  });

  // Lazy-load view contents
  if (viewId === "viewMitre") {
    loadMitreMatrix();
  } else if (viewId === "viewDissect") {
    loadPacketDissection();
  } else if (viewId === "viewTriage") {
    loadTriageReport(latestAlertId);
  } else if (viewId === "viewRules") {
    loadMitigationRules(latestAlertId);
  }
}

tabButtons.forEach(btn => {
  btn.addEventListener("click", () => {
    switchView(btn.dataset.view);
  });
});

// -------------------------------------------------------------
// WebSocket Live Connection
// -------------------------------------------------------------
function initWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/ws/live`;

  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    connStatus.textContent = "WEBSOCKET ONLINE";
    connStatus.className = "status-pill pill-online";
  };

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      handleTelemetryUpdate(data);
    } catch (e) {
      console.error("Telemetry parse error:", e);
    }
  };

  ws.onclose = () => {
    connStatus.textContent = "STREAM RECONNECTING...";
    connStatus.className = "status-pill pill-offline";
    setTimeout(initWebSocket, 2000);
  };

  ws.onerror = () => {
    ws.close();
  };
}

// -------------------------------------------------------------
// Telemetry UI Updates
// -------------------------------------------------------------
function handleTelemetryUpdate(data) {
  // 1. KPI Top Strip
  const pps = data.sustained_pps || 0;
  if (metricPps) metricPps.textContent = pps.toLocaleString();
  if (metricMbps) metricMbps.textContent = `${data.instant_mbps || 0.0} Mbps // 16 Shards`;

  const totalPkts = data.total_packets || 0;
  if (metricPackets) metricPackets.textContent = totalPkts.toLocaleString();
  if (metricUptime) metricUptime.textContent = `Uptime: ${data.uptime_sec || 0.0}s`;
  if (metricFlows) metricFlows.textContent = `${data.active_flows || 0} Active Flows`;

  if (metricLatency) metricLatency.textContent = `${data.eval_latency_ms || 0.0} ms`;

  const alertsCount = data.alerts_count || 0;
  if (metricAlerts) metricAlerts.textContent = alertsCount.toLocaleString();

  const sev = data.severity_breakdown || {};
  if (metricSeveritySummary) {
    metricSeveritySummary.textContent = `${sev.CRITICAL || 0} Crit / ${sev.HIGH || 0} High / ${sev.MEDIUM || 0} Med / ${sev.LOW || 0} Low / ${sev.INFO || 0} Info`;
  }

  // Diode optical status
  if (diodeLed) {
    if ((sev.CRITICAL || 0) > 0) {
      diodeLed.style.background = "#f87171";
      diodeLed.style.boxShadow = "0 0 10px #f87171";
    } else {
      diodeLed.style.background = "#34d399";
      diodeLed.style.boxShadow = "0 0 8px #34d399";
    }
  }

  // 2. Alert Feed
  if (data.recent_alerts && data.recent_alerts.length > 0) {
    currentAlerts = data.recent_alerts;
    latestAlertId = currentAlerts[0].alert_id;
    renderAlertsTable();
  }

  // 3. Update Radar Beams from recent flows
  if (data.recent_flows && data.recent_flows.length > 0) {
    data.recent_flows.forEach(f => {
      let beamColor = "#38bdf8";
      if (f.dst === "192.168.1.1" && f.port === 80) beamColor = "#f87171"; // SYN Flood
      else if (f.dst === "203.0.113.88") beamColor = "#c084fc"; // C2 Beacon
      else if (f.src === "192.168.1.199") beamColor = "#fbbf24"; // Scan
      else if (f.dst === "185.220.101.5") beamColor = "#f87171"; // JA4 C2
      
      triggerRadarBeam(f.src, f.dst, beamColor);
    });
  }
}

// Helper: Escape HTML string safely
function escapeHtml(str) {
  if (!str) return "";
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// -------------------------------------------------------------
// Alerts Table Rendering & Quick Actions
// -------------------------------------------------------------
function renderAlertsTable() {
  if (!alertsTableBody) return;

  if (currentAlerts.length === 0) {
    alertsTableBody.innerHTML = `
      <tr>
        <td colspan="6" style="text-align: center; color: var(--text-dim); padding: 40px;">
          Passive sensor active. Awaiting threat indicators.
        </td>
      </tr>
    `;
    return;
  }

  alertsTableBody.innerHTML = currentAlerts.map(a => {
    // Authentic sub-second timestamp with jitter
    let timeStr = a.timestamp_str;
    if (!timeStr) {
      const d = new Date(a.timestamp * 1000);
      const ms = Math.floor(((a.timestamp % 1) + 1) % 1 * 1000).toString().padStart(3, "0");
      timeStr = `${d.toTimeString().substring(0, 8)}.${ms}`;
    }

    const targetFlow = `${a.src_ip} &rarr; ${a.dst_ip}${a.dst_port ? ":" + a.dst_port : ""}`;
    const confScore = a.confidence_score !== undefined ? a.confidence_score : 0.85;
    const confPct = Math.round(confScore * 100);

    // Color gradient for confidence bar
    let confColor = "#38bdf8";
    if (confPct >= 85) confColor = "#f87171";
    else if (confPct >= 70) confColor = "#fbbf24";
    else if (confPct >= 40) confColor = "#22d3ee";
    else confColor = "#94a3b8";

    let sevPillClass = "pill-low";
    if (a.severity === "CRITICAL") sevPillClass = "pill-critical";
    else if (a.severity === "HIGH") sevPillClass = "pill-high";
    else if (a.severity === "MEDIUM") sevPillClass = "pill-medium";
    else if (a.severity === "LOW") sevPillClass = "pill-low";
    else if (a.severity === "INFO") sevPillClass = "pill-info";

    // Deviant / ambient log context details (human typos, traces, certificates)
    let detailNote = "";
    if (a.description && (a.threat_class === "DEV_ERROR" || a.threat_class === "DNS_NXDOMAIN" || a.threat_class === "AUTH_FAILURE" || a.threat_class === "POLICY_VIOLATION" || a.threat_class === "ANOMALOUS_USER_AGENT")) {
      detailNote = `<div style="font-size: 0.62rem; color: #94a3b8; font-weight: normal; margin-top: 2px; font-family: var(--font-mono); max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(a.description)}">${escapeHtml(a.description)}</div>`;
    }

    return `
      <tr>
        <td style="font-family: var(--font-mono); color: var(--text-dim); font-size: 0.70rem; letter-spacing: -0.2px;">${timeStr}</td>
        <td><span class="sev-pill ${sevPillClass}">${a.severity}</span></td>
        <td style="font-weight: 700; color: #fff;">
          <div>${a.threat_class}</div>
          ${detailNote}
        </td>
        <td style="font-family: var(--font-mono); font-size: 0.71rem; color: #38bdf8;">${targetFlow}</td>
        <td>
          <div class="conf-cell">
            <span class="conf-val" style="color: ${confColor};">${confPct}%</span>
            <div class="conf-mini-bar">
              <div class="conf-mini-fill" style="width: ${confPct}%; background: ${confColor};"></div>
            </div>
          </div>
        </td>
        <td>
          <div style="display: flex; gap: 4px;">
            <button class="btn-table-action" onclick="triageAlert('${a.alert_id}')" title="AI Incident Triage">Triage</button>
            <button class="btn-table-action" onclick="dissectAlert('${a.alert_id}')" title="Inspect Raw Frame">Dissect</button>
            <button class="btn-table-action" onclick="rulesAlert('${a.alert_id}')" title="Synthesize Rules">Rules</button>
          </div>
        </td>
      </tr>
    `;
  }).join("");
}

// Action helpers from table rows
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

window.rulesAlert = function(alertId) {
  latestAlertId = alertId;
  switchView("viewRules");
  loadMitigationRules(alertId);
};

document.getElementById("btnClearAlerts")?.addEventListener("click", () => {
  currentAlerts = [];
  renderAlertsTable();
  showToast("Alert stream cleared", "🗑️");
});

// -------------------------------------------------------------
// Interactive Attack Injection Actions
// -------------------------------------------------------------
async function triggerAttack(type, payload = {}) {
  try {
    const res = await fetch("/api/inject", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type, ...payload })
    });
    const result = await res.json();
    if (result.status === "ok") {
      showToast(result.message, "🚨");
    } else {
      showToast(result.message || "Failed to inject attack", "⚠️");
    }
  } catch (err) {
    showToast("Error connecting to threat engine API", "❌");
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

document.getElementById("btnReplayPcap")?.addEventListener("click", async () => {
  showToast("Replaying multi-threat PCAP capture...", "📼");
  try {
    const res = await fetch("/api/pcap/replay_sample", { method: "POST" });
    const data = await res.json();
    showToast(`Replayed ${data.replayed_packets} packets from ${data.pcap_name}`, "✅");
  } catch (err) {
    showToast("Failed to replay sample PCAP", "❌");
  }
});

// Rate Slider & Presets
async function setTargetRate(pps) {
  if (rateSlider) rateSlider.value = pps;
  if (rateValueDisplay) rateValueDisplay.textContent = `${pps.toLocaleString()} pps`;
  try {
    await fetch("/api/rate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pps })
    });
  } catch (e) {}
}

rateSlider?.addEventListener("input", (e) => {
  const val = parseInt(e.target.value);
  if (rateValueDisplay) rateValueDisplay.textContent = `${val.toLocaleString()} pps`;
});

rateSlider?.addEventListener("change", (e) => {
  setTargetRate(parseInt(e.target.value));
});

document.getElementById("btnPreset5k")?.addEventListener("click", () => setTargetRate(5000));
document.getElementById("btnPreset25k")?.addEventListener("click", () => setTargetRate(25000));
document.getElementById("btnPreset50k")?.addEventListener("click", () => setTargetRate(50000));

// Toggle Generator Pause/Resume
btnToggleGen?.addEventListener("click", async () => {
  try {
    const res = await fetch("/api/generator/toggle", { method: "POST" });
    const data = await res.json();
    if (data.is_running) {
      if (genToggleText) genToggleText.textContent = "Pause Stream";
      showToast("Traffic stream active", "▶️");
    } else {
      if (genToggleText) genToggleText.textContent = "Resume Stream";
      showToast("Traffic stream paused", "⏸️");
    }
  } catch (e) {}
});

// -------------------------------------------------------------
// MITRE ATT&CK Enterprise Matrix View
// -------------------------------------------------------------
async function loadMitreMatrix() {
  const grid = document.getElementById("mitreMatrixGrid");
  if (!grid) return;

  grid.innerHTML = `<div style="grid-column: span 14; text-align: center; color: var(--text-dim); padding: 40px;">Querying MITRE ATT&CK v15 Matrix state...</div>`;

  try {
    const res = await fetch("/api/mitre/matrix");
    const data = await res.json();

    if (mitreHitBadge) {
      const activeTotal = data.active_techniques ? data.active_techniques.length : 0;
      mitreHitBadge.textContent = `${activeTotal} Active`;
    }

    if (!data.tactics || data.tactics.length === 0) {
      grid.innerHTML = `<div style="grid-column: span 14; text-align: center; color: var(--text-dim);">No MITRE tactics configured.</div>`;
      return;
    }

    grid.innerHTML = data.tactics.map(t => {
      const techCards = (t.techniques || []).map(tech => {
        const isActive = tech.active ? "active-tech" : "";
        const alertBadge = tech.alert_count > 0 ? `<span class="tech-badge">${tech.alert_count}</span>` : "";
        const threatsStr = (tech.threats || []).join(", ");
        return `
          <div class="mitre-tech-card ${isActive}" onclick="inspectMitreTech('${tech.id}', '${tech.name}')" title="${threatsStr ? 'Correlated: ' + threatsStr : tech.name}">
            <div class="tech-id">${tech.id}</div>
            <div class="tech-name">${tech.name}</div>
            ${alertBadge}
          </div>
        `;
      }).join("");

      return `
        <div class="mitre-tactic-col">
          <div class="mitre-tactic-title">
            <span>${t.name}</span>
            <span style="color: #94a3b8;">${t.active_count > 0 ? t.active_count : ''}</span>
          </div>
          ${techCards}
        </div>
      `;
    }).join("");
  } catch (err) {
    grid.innerHTML = `<div style="grid-column: span 14; color: #f87171; padding: 20px;">Failed to load MITRE ATT&CK Matrix: ${err.message}</div>`;
  }
}

window.inspectMitreTech = function(techId, techName) {
  showToast(`Filtering on MITRE Technique ${techId}: ${techName}`, "🛡️");
  switchView("viewTriage");
  loadTriageReport();
};

document.getElementById("btnRefreshMitre")?.addEventListener("click", loadMitreMatrix);

// -------------------------------------------------------------
// Packet Dissector & Raw Hex Inspection View
// -------------------------------------------------------------
async function loadPacketDissection(alertId = null) {
  if (!packetTreeContainer || !hexDumpContainer) return;

  packetTreeContainer.innerHTML = `<div style="color: var(--text-dim); padding: 20px;">Dissecting raw frame byte stream...</div>`;
  hexDumpContainer.textContent = "Dissecting frame bytes...";

  try {
    const url = alertId ? `/api/dissect/packet?alert_id=${alertId}` : `/api/dissect/packet`;
    const res = await fetch(url);
    const data = await res.json();

    const pkt = (data.packets && data.packets.length > 0) ? data.packets[0] : null;
    if (!pkt) {
      packetTreeContainer.innerHTML = `<div style="color: var(--text-dim); padding: 20px;">No frames captured yet. Stream active.</div>`;
      return;
    }

    // 1. Render Protocol Tree Layers
    const layersHtml = (pkt.layers || []).map((layer, idx) => `
      <div class="tree-layer-box">
        <div class="tree-layer-head">
          <span style="font-weight: 600; color: #e2e8f0;">▶ [Layer ${idx + 1}] ${layer.name}</span>
        </div>
        <div class="tree-layer-body" style="padding: 6px 12px; font-family: var(--font-mono); font-size: 0.72rem; color: #94a3b8;">
          ${layer.info}
        </div>
      </div>
    `).join("");

    packetTreeContainer.innerHTML = `
      <div style="font-family: var(--font-mono); font-size: 0.72rem; color: #38bdf8; margin-bottom: 8px; padding-bottom: 4px; border-bottom: 1px solid var(--border-subtle);">
        FRAME #${pkt.frame_num || 1} // ${pkt.src || '192.168.1.77'} &rarr; ${pkt.dst || '185.220.101.5'} // ${pkt.protocol || 'TCP'} (${pkt.length || 512} bytes)
      </div>
      ${layersHtml}
    `;

    // 2. Render Wireshark-Style Hex Dump
    if (pkt.hex_dump) {
      hexDumpContainer.textContent = pkt.hex_dump;
    } else if (data.hex_stream) {
      hexDumpContainer.textContent = formatWiresharkHexDump(data.hex_stream);
    }
  } catch (err) {
    packetTreeContainer.innerHTML = `<div style="color: #f87171; padding: 20px;">Error dissecting packet: ${err.message}</div>`;
  }
}

function formatWiresharkHexDump(hexString) {
  const bytes = [];
  for (let i = 0; i < hexString.length; i += 2) {
    bytes.push(hexString.substr(i, 2));
  }

  const lines = [];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const chunk = bytes.slice(offset, offset + 16);
    const offsetHex = offset.toString(16).padStart(4, "0");

    // Format hex section (with center gap after 8 bytes)
    const first8 = chunk.slice(0, 8).join(" ");
    const last8 = chunk.slice(8, 16).join(" ");
    const hexPart = `${first8.padEnd(23, " ")}  ${last8.padEnd(23, " ")}`;

    // Format ASCII section
    const asciiPart = chunk.map(b => {
      const code = parseInt(b, 16);
      return (code >= 32 && code <= 126) ? String.fromCharCode(code) : ".";
    }).join("");

    lines.push(`${offsetHex}   ${hexPart}  |${asciiPart}|`);
  }

  return lines.join("\n") || "0000   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|";
}

document.getElementById("btnRefreshDissect")?.addEventListener("click", () => loadPacketDissection());

// -------------------------------------------------------------
// AI Incident Triage Dossier View
// -------------------------------------------------------------
async function loadTriageReport(alertId = null) {
  if (!triageSummary) return;

  triageSummary.textContent = "Analyzing telemetry and executing autonomous incident triage heuristics...";

  try {
    const res = await fetch("/api/ai/triage", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alert_id: alertId })
    });
    const data = await res.json();

    if (data.status !== "ok") {
      triageSummary.textContent = data.message || "Incident triage unavailable.";
      return;
    }

    const t = data.triage;
    if (triageTitle) triageTitle.textContent = `INCIDENT TRIAGE DOSSIER // ${t.incident_id || 'INC-001'}`;
    if (triageThreatClass) triageThreatClass.textContent = t.threat_class || "UNKNOWN";
    if (triageSevConf) triageSevConf.textContent = `${t.severity || 'CRITICAL'} (${Math.round((t.confidence_score || 0.95) * 100)}%)`;
    if (triageMitreId) triageMitreId.textContent = `${t.mitre_technique_id} (${t.mitre_tactic})`;
    if (triageActor) triageActor.textContent = t.adversary_profile ? t.adversary_profile.actor_attribution : "Unattributed Cluster";

    if (triageSummary) triageSummary.textContent = t.executive_summary || "No summary generated.";
    if (triageBlastRadius) {
      triageBlastRadius.innerHTML = `
        <div style="margin-bottom: 6px;"><strong>Target Blast Radius:</strong> ${t.blast_radius_analysis || 'Subnet confined'}</div>
        <div><strong>Lateral Movement Risk:</strong> ${t.lateral_movement_exposure || 'Contained'}</div>
      `;
    }

    if (triagePlaybook && t.containment_playbook) {
      triagePlaybook.innerHTML = t.containment_playbook.map(step => `
        <div class="playbook-step">
          <div class="playbook-step-num">${step.step}</div>
          <div class="playbook-step-content">
            <div class="playbook-step-title">[${step.priority}] ${step.action}</div>
            <pre class="playbook-step-cmd">${step.command}</pre>
          </div>
        </div>
      `).join("");
    }
  } catch (err) {
    if (triageSummary) triageSummary.textContent = `Error compiling triage dossier: ${err.message}`;
  }
}

document.getElementById("btnReTriageLatest")?.addEventListener("click", () => loadTriageReport());
document.getElementById("btnExportBrief")?.addEventListener("click", () => {
  const briefText = `${triageTitle?.textContent}\nThreat: ${triageThreatClass?.textContent}\nSeverity: ${triageSevConf?.textContent}\nMITRE: ${triageMitreId?.textContent}\nActor: ${triageActor?.textContent}\n\nExecutive Summary:\n${triageSummary?.textContent}\n\nBlast Radius:\n${triageBlastRadius?.innerText}`;
  navigator.clipboard.writeText(briefText).then(() => {
    showToast("Tactical executive brief copied to clipboard", "📋");
  });
});

// -------------------------------------------------------------
// Mitigation Rules View & Clipboard Copying
// -------------------------------------------------------------
async function loadMitigationRules(alertId = null) {
  try {
    const res = await fetch("/api/ai/synthesize_rule", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alert_id: alertId })
    });
    const data = await res.json();

    if (data.status === "ok" && data.rules) {
      if (ruleIptables) ruleIptables.textContent = data.rules.iptables || "# iptables rule generated";
      if (ruleNftables) ruleNftables.textContent = data.rules.nftables || "# nftables rule generated";
      if (ruleSuricata) ruleSuricata.textContent = data.rules.suricata || "# Suricata rule generated";
      if (ruleSnort) ruleSnort.textContent = data.rules.snort || "# Snort rule generated";
      if (rulePfsense) rulePfsense.textContent = data.rules.pfsense || "<!-- pfSense XML generated -->";
    }
  } catch (e) {
    console.error("Rule synthesis error:", e);
  }
}

window.copyRule = function(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;

  const text = el.textContent || el.innerText;
  navigator.clipboard.writeText(text).then(() => {
    showToast("Firewall rule copied to clipboard", "📋");
  }).catch(() => {
    showToast("Unable to copy to clipboard", "⚠️");
  });
};

// -------------------------------------------------------------
// Security Analyst Terminal Console
// -------------------------------------------------------------
async function executeAnalystCommand(query) {
  if (!query || !query.trim()) return;
  const q = query.trim();

  // 1. Append user prompt entry
  const userEntry = document.createElement("div");
  userEntry.className = "term-entry-user";
  userEntry.textContent = `analyst@cybershield:~$ ${q}`;
  termHistory.appendChild(userEntry);

  if (termInput) termInput.value = "";
  termHistory.scrollTop = termHistory.scrollHeight;

  // 2. Query backend AI Intelligence
  try {
    const res = await fetch("/api/ai/query", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: q })
    });
    const data = await res.json();

    const aiEntry = document.createElement("div");
    aiEntry.className = "term-entry-ai";
    aiEntry.textContent = data.response || "No response received from sensor core.";
    termHistory.appendChild(aiEntry);
  } catch (err) {
    const errEntry = document.createElement("div");
    errEntry.className = "term-entry-ai";
    errEntry.style.color = "#f87171";
    errEntry.textContent = `[SYSTEM ERROR] Communication failure: ${err.message}`;
    termHistory.appendChild(errEntry);
  }

  termHistory.scrollTop = termHistory.scrollHeight;
}

termInput?.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    executeAnalystCommand(termInput.value);
  }
});

btnTermSend?.addEventListener("click", () => {
  executeAnalystCommand(termInput.value);
});

// Quick command buttons
document.getElementById("btnQueryStatus")?.addEventListener("click", () => {
  executeAnalystCommand("status");
});
document.getElementById("btnQueryMitre")?.addEventListener("click", () => {
  executeAnalystCommand("mitre");
});
document.getElementById("btnQueryIsolate")?.addEventListener("click", () => {
  executeAnalystCommand("isolate host 192.168.1.105");
});
document.getElementById("btnQueryJa4")?.addEventListener("click", () => {
  executeAnalystCommand("ja4 analysis");
});

// -------------------------------------------------------------
// Interactive 60fps HTML5 Canvas Radar Visualizer
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
    { label: "192.168.1.1 (Gateway)", x: cx, y: cy, type: "internal", color: "#34d399" },
    { label: "172.16.x.x (Spoofed SYN)", angle: 0.2, dist: radius * 0.9, type: "hostile", color: "#f87171" },
    { label: "203.0.113.88 (C2 Beacon)", angle: 1.8, dist: radius * 0.85, type: "hostile", color: "#c084fc" },
    { label: "192.168.1.199 (Port Scanner)", angle: 3.2, dist: radius * 0.75, type: "scanner", color: "#fbbf24" },
    { label: "185.220.101.5 (JA4 C2)", angle: 4.5, dist: radius * 0.88, type: "hostile", color: "#f87171" },
    { label: "93.184.216.34 (Benign Web)", angle: 5.4, dist: radius * 0.65, type: "benign", color: "#38bdf8" }
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
    speed: 0.04 + Math.random() * 0.04,
    color: color
  });
}

function drawRadar() {
  if (!canvas || !ctx) return;
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  const cx = canvas.width / 2;
  const cy = canvas.height / 2;
  const maxRadius = Math.min(cx, cy) * 0.85;

  // 1. Concentric Range Circles
  for (let r = 0.25; r <= 1.0; r += 0.25) {
    ctx.beginPath();
    ctx.arc(cx, cy, maxRadius * r, 0, Math.PI * 2);
    ctx.strokeStyle = "rgba(56, 189, 248, 0.12)";
    ctx.lineWidth = 1;
    ctx.stroke();

    ctx.font = "10px JetBrains Mono";
    ctx.fillStyle = "rgba(148, 163, 184, 0.4)";
    ctx.fillText(`${Math.round(r * 100)}%`, cx + 4, cy - maxRadius * r + 12);
  }

  // Crosshairs
  ctx.beginPath();
  ctx.moveTo(cx - maxRadius, cy);
  ctx.lineTo(cx + maxRadius, cy);
  ctx.moveTo(cx, cy - maxRadius);
  ctx.lineTo(cx, cy + maxRadius);
  ctx.strokeStyle = "rgba(56, 189, 248, 0.1)";
  ctx.stroke();

  // 2. Sweeping Radar Beam
  radarAngle += 0.025;
  if (radarAngle >= Math.PI * 2) radarAngle = 0;

  const sweepGradient = ctx.createRadialGradient(cx, cy, 0, cx, cy, maxRadius);
  sweepGradient.addColorStop(0, "rgba(56, 189, 248, 0.0)");
  sweepGradient.addColorStop(1, "rgba(56, 189, 248, 0.18)");

  ctx.save();
  ctx.beginPath();
  ctx.moveTo(cx, cy);
  ctx.arc(cx, cy, maxRadius, radarAngle - 0.35, radarAngle);
  ctx.closePath();
  ctx.fillStyle = sweepGradient;
  ctx.fill();

  ctx.beginPath();
  ctx.moveTo(cx, cy);
  ctx.lineTo(cx + Math.cos(radarAngle) * maxRadius, cy + Math.sin(radarAngle) * maxRadius);
  ctx.strokeStyle = "rgba(56, 189, 248, 0.6)";
  ctx.lineWidth = 1.5;
  ctx.stroke();
  ctx.restore();

  // 3. Central Monitored Enclave Node
  ctx.beginPath();
  ctx.arc(cx, cy, 8, 0, Math.PI * 2);
  ctx.fillStyle = "#34d399";
  ctx.shadowColor = "#34d399";
  ctx.shadowBlur = 10;
  ctx.fill();
  ctx.shadowBlur = 0;

  ctx.font = "10px JetBrains Mono";
  ctx.fillStyle = "#34d399";
  ctx.fillText("AIR-GAPPED ENCLAVE (192.168.1.0/24)", cx - 110, cy + 24);

  // 4. Perimeter Threat & Host Nodes
  radarNodes.forEach(node => {
    if (node.type === "internal") return;
    const nx = cx + Math.cos(node.angle) * node.dist;
    const ny = cy + Math.sin(node.angle) * node.dist;

    ctx.beginPath();
    ctx.arc(nx, ny, 5, 0, Math.PI * 2);
    ctx.fillStyle = node.color;
    ctx.shadowColor = node.color;
    ctx.shadowBlur = 8;
    ctx.fill();
    ctx.shadowBlur = 0;

    ctx.font = "9px JetBrains Mono";
    ctx.fillStyle = "#94a3b8";
    ctx.fillText(node.label, nx + 8, ny + 3);
  });

  // 5. Active Inbound Attack & Traffic Beams
  for (let i = activeBeams.length - 1; i >= 0; i--) {
    const beam = activeBeams[i];
    beam.progress += beam.speed;

    const curX = beam.startX + (beam.targetX - beam.startX) * beam.progress;
    const curY = beam.startY + (beam.targetY - beam.startY) * beam.progress;

    ctx.beginPath();
    ctx.arc(curX, curY, 3, 0, Math.PI * 2);
    ctx.fillStyle = beam.color;
    ctx.shadowColor = beam.color;
    ctx.shadowBlur = 10;
    ctx.fill();
    ctx.shadowBlur = 0;

    // Laser trail
    ctx.beginPath();
    ctx.moveTo(beam.startX, beam.startY);
    ctx.lineTo(curX, curY);
    ctx.strokeStyle = beam.color;
    ctx.lineWidth = 1.2;
    ctx.stroke();

    if (beam.progress >= 1.0) {
      activeBeams.splice(i, 1);
    }
  }

  requestAnimationFrame(drawRadar);
}

if (canvas) {
  requestAnimationFrame(drawRadar);
}

// Initialize WebSocket stream on page load
initWebSocket();
