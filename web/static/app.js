/**
 * CYBERSHIELD // Unidirectional Passive Threat Sensor Client
 * Handles real-time WebSockets, 60fps canvas radar, attack controls, and forensic modal.
 */

// Global State
let ws = null;
let currentAlerts = [];
let activeFilter = "ALL";
let isPaused = false;
let radarNodes = [];
let activeBeams = [];
let radarAngle = 0;

// DOM Elements
const sysClock = document.getElementById("sysClock");
const connStatus = document.getElementById("connStatus");
const diodeLed = document.getElementById("diodeLed");
const metricPps = document.getElementById("metricPps");
const metricMbps = document.getElementById("metricMbps");
const metricPackets = document.getElementById("metricPackets");
const metricUptime = document.getElementById("metricUptime");
const metricFlows = document.getElementById("metricFlows");
const metricLatency = document.getElementById("metricLatency");
const metricAlerts = document.getElementById("metricAlerts");
const badgeCrit = document.getElementById("badgeCrit");
const badgeHigh = document.getElementById("badgeHigh");
const badgeMed = document.getElementById("badgeMed");
const alertsTableBody = document.getElementById("alertsTableBody");
const rateSlider = document.getElementById("rateSlider");
const rateValueDisplay = document.getElementById("rateValueDisplay");
const btnToggleGen = document.getElementById("btnToggleGen");
const genToggleText = document.getElementById("genToggleText");
const siemStatusText = document.getElementById("siemStatusText");
const toastContainer = document.getElementById("toastContainer");

// Modal Elements
const modalForensics = document.getElementById("modalForensics");
const modalCloseBtn = document.getElementById("modalCloseBtn");
const btnModalClose = document.getElementById("btnModalClose");
const modalSevPill = document.getElementById("modalSevPill");
const modalThreatClass = document.getElementById("modalThreatClass");
const modalConfidence = document.getElementById("modalConfidence");
const modalSrc = document.getElementById("modalSrc");
const modalDst = document.getElementById("modalDst");
const modalEvidenceJson = document.getElementById("modalEvidenceJson");
const modalCefString = document.getElementById("modalCefString");
const btnCopyCef = document.getElementById("btnCopyCef");

// -------------------------------------------------------------
// System Clock
// -------------------------------------------------------------
function updateClock() {
  const now = new Date();
  sysClock.textContent = now.toISOString().substring(11, 19) + " UTC";
}
setInterval(updateClock, 1000);
updateClock();

// -------------------------------------------------------------
// Toast Notifications
// -------------------------------------------------------------
function showToast(message, icon = "⚡") {
  const toast = document.createElement("div");
  toast.className = "toast-msg";
  toast.innerHTML = `<span>${icon}</span><span>${message}</span>`;
  toastContainer.appendChild(toast);
  setTimeout(() => {
    toast.style.transition = "opacity 0.4s, transform 0.4s";
    toast.style.opacity = "0";
    toast.style.transform = "translateX(100%)";
    setTimeout(() => toast.remove(), 400);
  }, 3200);
}

// -------------------------------------------------------------
// WebSocket Live Connection
// -------------------------------------------------------------
function initWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/ws/live`;

  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    connStatus.textContent = "● WEBSOCKET STREAM ACTIVE";
    connStatus.style.color = "var(--accent-emerald)";
    connStatus.style.borderColor = "rgba(0, 255, 157, 0.4)";
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
    connStatus.textContent = "○ STREAM DISCONNECTED (RETRYING...)";
    connStatus.style.color = "var(--accent-crimson)";
    connStatus.style.borderColor = "rgba(255, 0, 85, 0.4)";
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
  // 1. KPI Cards
  const pps = data.sustained_pps || 0;
  metricPps.textContent = pps.toLocaleString();
  metricMbps.textContent = `${data.instant_mbps || 0.0} Mbps`;

  const totalPkts = data.total_packets || 0;
  metricPackets.textContent = totalPkts.toLocaleString();
  metricUptime.textContent = `Uptime: ${data.uptime_sec || 0}s`;
  metricFlows.textContent = `${data.active_flows || 0} active flows`;

  metricLatency.textContent = `${data.eval_latency_ms || 0.0} ms`;
  
  const alertsCount = data.alerts_count || 0;
  metricAlerts.textContent = alertsCount;
  const sev = data.severity_breakdown || {};
  badgeCrit.textContent = `${sev.CRITICAL || 0} Crit`;
  badgeHigh.textContent = `${sev.HIGH || 0} High`;
  badgeMed.textContent = `${sev.MEDIUM || 0} Med`;

  // Diode alert LED
  if (sev.CRITICAL > 0) {
    diodeLed.classList.add("alerting");
  } else {
    diodeLed.classList.remove("alerting");
  }

  // 2. Alert Feed
  if (data.recent_alerts) {
    currentAlerts = data.recent_alerts;
    renderAlertsTable();
  }

  // 3. Update Radar Beams from recent flows
  if (data.recent_flows && data.recent_flows.length > 0) {
    data.recent_flows.forEach(f => {
      // Map flow into visual laser beam
      let beamColor = "#00f0ff";
      if (f.dst === "192.168.1.1" && f.port === 80) beamColor = "#ff0055"; // SYN flood
      else if (f.dst === "203.0.113.88") beamColor = "#b026ff"; // C2 Beacon
      else if (f.src === "192.168.1.199") beamColor = "#ffb800"; // Scan
      
      triggerRadarBeam(f.src, f.dst, beamColor);
    });
  }

  // 4. SIEM status
  if (data.siem && data.siem.webhook_configured) {
    siemStatusText.textContent = `Webhook: ${data.siem.webhook_url.substring(0, 20)}...`;
  }
}

// -------------------------------------------------------------
// Alerts Table Rendering & Filtering
// -------------------------------------------------------------
function renderAlertsTable() {
  const filter = activeFilter;
  const filtered = currentAlerts.filter(a => {
    if (filter === "ALL") return true;
    if (filter === "JA4_DNS") {
      return a.threat_class.includes("JA4") || a.threat_class.includes("DNS") || a.threat_class.includes("DGA");
    }
    return a.severity === filter;
  });

  // Update tab counts
  document.getElementById("tabAll").textContent = `ALL (${currentAlerts.length})`;
  document.getElementById("tabCritical").textContent = `CRITICAL (${currentAlerts.filter(a => a.severity === "CRITICAL").length})`;
  document.getElementById("tabHigh").textContent = `HIGH (${currentAlerts.filter(a => a.severity === "HIGH").length})`;
  document.getElementById("tabMedium").textContent = `MEDIUM (${currentAlerts.filter(a => a.severity === "MEDIUM").length})`;

  if (filtered.length === 0) {
    alertsTableBody.innerHTML = `
      <tr>
        <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 40px;">
          No threat alerts matching filter "${filter}".
        </td>
      </tr>
    `;
    return;
  }

  alertsTableBody.innerHTML = filtered.map(a => {
    const timeStr = new Date(a.timestamp * 1000).toTimeString().substring(0, 8);
    const targetFlow = `${a.src_ip} &rarr; ${a.dst_ip}${a.dst_port ? ":" + a.dst_port : ""}`;
    const confPct = Math.round(a.confidence_score * 100);

    return `
      <tr class="alert-row">
        <td style="font-family: var(--font-mono); color: var(--text-muted);">${timeStr}</td>
        <td><span class="sev-pill sev-${a.severity}">${a.severity}</span></td>
        <td style="font-weight: 700; color: #fff;">${a.threat_class}</td>
        <td style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--accent-cyan);">${targetFlow}</td>
        <td style="font-family: var(--font-mono); font-weight: 700;">${confPct}%</td>
        <td>
          <button class="btn-inspect" onclick="inspectAlert('${a.alert_id}')">Inspect</button>
        </td>
      </tr>
    `;
  }).join("");
}

// Filter Tab Click Handlers
document.querySelectorAll(".filter-tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".filter-tab").forEach(t => t.classList.remove("active"));
    tab.classList.add("active");
    activeFilter = tab.dataset.filter;
    renderAlertsTable();
  });
});

document.getElementById("btnClearAlerts").addEventListener("click", () => {
  currentAlerts = [];
  renderAlertsTable();
  showToast("Alert table view cleared", "🗑️");
});

// -------------------------------------------------------------
// Forensic Evidence Modal
// -------------------------------------------------------------
window.inspectAlert = function(alertId) {
  const alert = currentAlerts.find(a => a.alert_id === alertId);
  if (!alert) return;

  modalThreatClass.textContent = alert.threat_class;
  modalSevPill.textContent = alert.severity;
  modalSevPill.className = `sev-pill sev-${alert.severity}`;
  modalConfidence.textContent = `${Math.round(alert.confidence_score * 100)}%`;
  modalSrc.textContent = alert.src_ip;
  modalDst.textContent = `${alert.dst_ip}${alert.dst_port ? ":" + alert.dst_port : ""}`;
  modalEvidenceJson.textContent = JSON.stringify(alert.evidence, null, 2);

  // Generate CEF string
  const cef = `CEF:0|PassiveDiode|ThreatEnclave|2.0|${alert.threat_class}|${alert.threat_class}|8|src=${alert.src_ip} dst=${alert.dst_ip} dpt=${alert.dst_port} cn1=${alert.confidence_score} cn1Label=Confidence`;
  modalCefString.textContent = cef;

  modalForensics.classList.add("open");
};

function closeModal() {
  modalForensics.classList.remove("open");
}

modalCloseBtn.addEventListener("click", closeModal);
btnModalClose.addEventListener("click", closeModal);
modalForensics.addEventListener("click", (e) => {
  if (e.target === modalForensics) closeModal();
});

btnCopyCef.addEventListener("click", () => {
  navigator.clipboard.writeText(modalCefString.textContent).then(() => {
    showToast("CEF SIEM string copied to clipboard", "📋");
  });
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

document.getElementById("btnInjectSyn").addEventListener("click", () => {
  triggerAttack("SYN_FLOOD", { target_ip: "192.168.1.1", port: 80 });
});

document.getElementById("btnInjectBeacon").addEventListener("click", () => {
  triggerAttack("C2_BEACON", { bot_ip: "192.168.1.105", c2_ip: "203.0.113.88" });
});

document.getElementById("btnInjectScan").addEventListener("click", () => {
  triggerAttack("PORT_SCAN", { scanner_ip: "192.168.1.199", target_ip: "10.0.0.5" });
});

document.getElementById("btnInjectDga").addEventListener("click", () => {
  triggerAttack("DGA", { client_ip: "192.168.1.45" });
});

document.getElementById("btnInjectJa4").addEventListener("click", () => {
  triggerAttack("JA4", { client_ip: "192.168.1.77", c2_ip: "185.220.101.5" });
});

// Replay Sample PCAP
document.getElementById("btnReplayPcap").addEventListener("click", async () => {
  showToast("Replaying multi-threat PCAP capture...", "📼");
  try {
    const res = await fetch("/api/pcap/replay_sample", { method: "POST" });
    const data = await res.json();
    showToast(`Replayed ${data.replayed_packets} packets from ${data.pcap_name}`, "✅");
  } catch (err) {
    showToast("Failed to replay sample PCAP", "❌");
  }
});

// Custom PCAP File Upload
const pcapFileInput = document.getElementById("pcapFileInput");
document.getElementById("btnUploadPcapTrigger").addEventListener("click", () => {
  pcapFileInput.click();
});

pcapFileInput.addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;

  showToast(`Uploading and parsing ${file.name}...`, "⏳");
  const formData = new FormData();
  formData.append("pcap_file", file);

  try {
    const res = await fetch("/api/pcap/upload", {
      method: "POST",
      body: formData
    });
    const result = await res.json();
    if (result.status === "ok") {
      showToast(`Analyzed ${result.processed_packets} packets from ${result.filename}`, "✅");
    } else {
      showToast(result.message || "PCAP parsing failed", "❌");
    }
  } catch (err) {
    showToast("Failed to upload PCAP file", "❌");
  }
  pcapFileInput.value = "";
});

// Rate Slider & Presets
async function setTargetRate(pps) {
  rateSlider.value = pps;
  rateValueDisplay.textContent = `${pps.toLocaleString()} pps`;
  try {
    await fetch("/api/rate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pps })
    });
  } catch (e) {}
}

rateSlider.addEventListener("input", (e) => {
  const val = parseInt(e.target.value);
  rateValueDisplay.textContent = `${val.toLocaleString()} pps`;
});

rateSlider.addEventListener("change", (e) => {
  setTargetRate(parseInt(e.target.value));
});

document.getElementById("btnPreset5k").addEventListener("click", () => setTargetRate(5000));
document.getElementById("btnPreset25k").addEventListener("click", () => setTargetRate(25000));
document.getElementById("btnPreset50k").addEventListener("click", () => setTargetRate(50000));

// Toggle Generator Pause/Resume
btnToggleGen.addEventListener("click", async () => {
  try {
    const res = await fetch("/api/generator/toggle", { method: "POST" });
    const data = await res.json();
    if (data.is_running) {
      genToggleText.textContent = "Pause Generator";
      showToast("Traffic generator resumed", "▶️");
    } else {
      genToggleText.textContent = "Resume Generator";
      showToast("Traffic generator paused", "⏸️");
    }
  } catch (e) {}
});

// SIEM Webhook Configuration
document.getElementById("btnConfigureSiem").addEventListener("click", async () => {
  const currentUrl = prompt("Enter external SIEM Webhook URL (e.g. https://siem.corp/webhook/alerts):", "");
  if (currentUrl !== null) {
    try {
      const res = await fetch("/api/siem", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ webhook_url: currentUrl })
      });
      const data = await res.json();
      showToast(currentUrl ? "SIEM webhook endpoint saved" : "SIEM webhook disabled", "🔗");
      siemStatusText.textContent = currentUrl ? `Webhook: ${currentUrl.substring(0, 20)}...` : "SIEM: Local JSONL";
    } catch (e) {
      showToast("Failed to update SIEM config", "❌");
    }
  }
});

// -------------------------------------------------------------
// Interactive 60fps HTML5 Canvas Radar Visualizer
// -------------------------------------------------------------
const canvas = document.getElementById("radarCanvas");
const ctx = canvas.getContext("2d");

function resizeCanvas() {
  const rect = canvas.parentElement.getBoundingClientRect();
  canvas.width = rect.width;
  canvas.height = rect.height;
}
window.addEventListener("resize", resizeCanvas);
resizeCanvas();

// Initialize Mock Threat Nodes around central monitored enclave
function initRadarNodes() {
  const cx = canvas.width / 2;
  const cy = canvas.height / 2;
  const radius = Math.min(cx, cy) * 0.75;

  radarNodes = [
    { label: "192.168.1.1 (Gateway)", x: cx, y: cy, type: "internal", color: "#00ff9d" },
    { label: "172.16.x.x (Spoofed SYN)", angle: 0.2, dist: radius * 0.9, type: "hostile", color: "#ff0055" },
    { label: "203.0.113.88 (C2 Beacon)", angle: 1.8, dist: radius * 0.85, type: "hostile", color: "#b026ff" },
    { label: "192.168.1.199 (Port Scanner)", angle: 3.2, dist: radius * 0.75, type: "scanner", color: "#ffb800" },
    { label: "185.220.101.5 (JA4 C2)", angle: 4.5, dist: radius * 0.88, type: "hostile", color: "#ff0055" },
    { label: "93.184.216.34 (Benign Web)", angle: 5.4, dist: radius * 0.65, type: "benign", color: "#00f0ff" }
  ];
}
initRadarNodes();

function triggerRadarBeam(src, dst, color) {
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
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  const cx = canvas.width / 2;
  const cy = canvas.height / 2;
  const maxRadius = Math.min(cx, cy) * 0.85;

  // 1. Concentric Range Circles
  for (let r = 0.25; r <= 1.0; r += 0.25) {
    ctx.beginPath();
    ctx.arc(cx, cy, maxRadius * r, 0, Math.PI * 2);
    ctx.strokeStyle = "rgba(0, 240, 255, 0.12)";
    ctx.lineWidth = 1;
    ctx.stroke();

    // Range distance text
    ctx.font = "10px JetBrains Mono";
    ctx.fillStyle = "rgba(0, 240, 255, 0.35)";
    ctx.fillText(`${Math.round(r * 100)}%`, cx + 4, cy - maxRadius * r + 12);
  }

  // Crosshairs
  ctx.beginPath();
  ctx.moveTo(cx - maxRadius, cy);
  ctx.lineTo(cx + maxRadius, cy);
  ctx.moveTo(cx, cy - maxRadius);
  ctx.lineTo(cx, cy + maxRadius);
  ctx.strokeStyle = "rgba(0, 240, 255, 0.1)";
  ctx.stroke();

  // 2. Sweeping Radar Beam
  radarAngle += 0.025;
  if (radarAngle >= Math.PI * 2) radarAngle = 0;

  const sweepGradient = ctx.createRadialGradient(cx, cy, 0, cx, cy, maxRadius);
  sweepGradient.addColorStop(0, "rgba(0, 240, 255, 0.0)");
  sweepGradient.addColorStop(1, "rgba(0, 240, 255, 0.18)");

  ctx.save();
  ctx.beginPath();
  ctx.moveTo(cx, cy);
  ctx.arc(cx, cy, maxRadius, radarAngle - 0.35, radarAngle);
  ctx.closePath();
  ctx.fillStyle = sweepGradient;
  ctx.fill();

  // Leading bright sweep line
  ctx.beginPath();
  ctx.moveTo(cx, cy);
  ctx.lineTo(cx + Math.cos(radarAngle) * maxRadius, cy + Math.sin(radarAngle) * maxRadius);
  ctx.strokeStyle = "rgba(0, 240, 255, 0.6)";
  ctx.lineWidth = 1.5;
  ctx.stroke();
  ctx.restore();

  // 3. Central Monitored Enclave Node
  ctx.beginPath();
  ctx.arc(cx, cy, 9, 0, Math.PI * 2);
  ctx.fillStyle = "#00ff9d";
  ctx.shadowColor = "#00ff9d";
  ctx.shadowBlur = 12;
  ctx.fill();
  ctx.shadowBlur = 0;

  ctx.font = "10px JetBrains Mono";
  ctx.fillStyle = "#00ff9d";
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

// Start visualizer loop
requestAnimationFrame(drawRadar);

// Initialize WebSocket stream on page load
initWebSocket();
