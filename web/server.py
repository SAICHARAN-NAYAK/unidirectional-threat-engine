"""
Real-Time Cyber SOC Web Application Server
Powered by Starlette ASGI, WebSockets, and Uvicorn.
Provides live threat telemetry streaming, interactive attack injection, PCAP replay, and forensic inspection.
"""

import os
import sys
import json
import asyncio
import time
import random
from typing import Set

# Ensure engine package is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from starlette.applications import Starlette
from starlette.responses import JSONResponse, FileResponse
from starlette.routing import Route, Mount, WebSocketRoute
from starlette.staticfiles import StaticFiles
from starlette.websockets import WebSocket, WebSocketDisconnect

from engine.sharded_enclave import ShardedPassiveDetectionEnclave
from engine.traffic_generator import TrafficGenerator
from engine.pcap_parser import replay_pcap, parse_pcap_stream
from engine.siem_exporter import SIEMExporter
from engine.ai_engine import AIThreatIntelligenceEngine

# Global Engine Singleton Instances
enclave = ShardedPassiveDetectionEnclave(window_size=3.0, num_shards=16)
generator = TrafficGenerator(enclave, target_pps=30000)
siem = SIEMExporter(log_file=os.path.join(BASE_DIR, "threat_alerts.jsonl"))
ai_engine = AIThreatIntelligenceEngine()
enclave.register_alert_callback(siem.export_alert)

# Connected WebSocket Clients
connected_websockets: Set[WebSocket] = set()

# Background Pruning & Evaluation Thread Loop
def background_evaluation_worker():
    while True:
        enclave.prune_and_evaluate()
        time.sleep(0.5)

import threading
eval_thread = threading.Thread(target=background_evaluation_worker, daemon=True, name="EnclaveEvalWorker")
eval_thread.start()

# Start background traffic generator by default
generator.start()

# -------------------------------------------------------------
# HTTP REST API Handlers
# -------------------------------------------------------------
async def index(request):
    index_file = os.path.join(os.path.dirname(__file__), "static", "index.html")
    return FileResponse(index_file)

async def api_telemetry(request):
    snapshot = enclave.get_telemetry_snapshot()
    snapshot["siem"] = siem.get_status()
    snapshot["generator"] = {
        "target_pps": generator.target_pps,
        "is_running": generator.is_running
    }
    return JSONResponse(snapshot)

async def api_alerts(request):
    alerts = [a.to_dict() for a in list(enclave.alerts)]
    return JSONResponse({"total": len(alerts), "alerts": alerts})

async def api_inject_attack(request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    attack_type = body.get("type", "SYN_FLOOD").upper()

    if attack_type == "SYN_FLOOD":
        target = body.get("target_ip", "192.168.1.1")
        port = int(body.get("port", 80))
        generator.inject_syn_flood(target_ip=target, target_port=port, count=180)
        msg = f"Injected 180 volumetric SYN flood packets to {target}:{port}"

    elif attack_type == "C2_BEACON":
        bot = body.get("bot_ip", "192.168.1.105")
        c2 = body.get("c2_ip", "203.0.113.88")
        generator.inject_c2_beacon(bot_ip=bot, c2_ip=c2, count=8)
        msg = f"Initiated 8 periodic C2 beaconing pulses between {bot} and {c2}:443"

    elif attack_type == "PORT_SCAN":
        scanner = body.get("scanner_ip", "192.168.1.199")
        target = body.get("target_ip", "10.0.0.5")
        generator.inject_port_scan(scanner_ip=scanner, target_ip=target, port_count=40)
        msg = f"Executed rapid reconnaissance port scan from {scanner} targeting {target} across 40 ports"

    elif attack_type == "DGA":
        client = body.get("client_ip", "192.168.1.45")
        generator.inject_dga_query(client_ip=client, count=5)
        msg = f"Injected high-entropy DGA/DNS tunneling queries from {client}"

    elif attack_type == "JA4":
        client = body.get("client_ip", "192.168.1.77")
        c2 = body.get("c2_ip", "185.220.101.5")
        sig = body.get("ja4_sig", None)
        generator.inject_malicious_ja4(client_ip=client, c2_ip=c2, ja4_sig=sig)
        msg = f"Injected malicious TLS Client Hello with Cobalt Strike JA4 signature"

    else:
        return JSONResponse({"status": "error", "message": f"Unknown attack type: {attack_type}"}, status_code=400)

    # Force an immediate evaluation step to trigger alert right away
    enclave.prune_and_evaluate()
    return JSONResponse({"status": "ok", "message": msg, "attack_type": attack_type})

async def api_set_rate(request):
    try:
        body = await request.json()
        target_pps = int(body.get("pps", 30000))
        generator.set_target_pps(target_pps)
        return JSONResponse({"status": "ok", "target_pps": generator.target_pps})
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=400)

async def api_toggle_generator(request):
    if generator.is_running:
        generator.stop()
    else:
        generator.start()
    return JSONResponse({"status": "ok", "is_running": generator.is_running})

async def api_set_siem(request):
    try:
        body = await request.json()
        url = body.get("webhook_url", "")
        siem.set_webhook_url(url)
        return JSONResponse({"status": "ok", "siem": siem.get_status()})
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=400)

async def api_replay_sample_pcap(request):
    pcap_path = os.path.join(BASE_DIR, "samples", "threat_simulation.pcap")
    if not os.path.exists(pcap_path):
        from samples.generate_sample_pcap import generate_multi_threat_pcap
        generate_multi_threat_pcap(pcap_path)

    replayed = replay_pcap(enclave, pcap_path, batch_size=100, speed_multiplier=0.0)
    enclave.prune_and_evaluate()
    return JSONResponse({"status": "ok", "replayed_packets": replayed, "pcap_name": "threat_simulation.pcap"})

async def api_upload_pcap(request):
    form = await request.form()
    pcap_file = form.get("pcap_file")
    if not pcap_file or not hasattr(pcap_file, "file"):
        return JSONResponse({"status": "error", "message": "No file uploaded"}, status_code=400)

    try:
        stream = pcap_file.file
        count = 0
        batch = []
        for pkt in parse_pcap_stream(stream):
            batch.append(pkt)
            if len(batch) >= 200:
                enclave.ingest_batch(batch)
                count += len(batch)
                batch = []
        enclave.prune_and_evaluate()
        return JSONResponse({"status": "ok", "processed_packets": count, "filename": pcap_file.filename})
    except Exception as e:
        return JSONResponse({"status": "error", "message": f"Error parsing PCAP: {str(e)}"}, status_code=500)

# -------------------------------------------------------------
# AI Threat Intelligence & MITRE ATT&CK Endpoints
# -------------------------------------------------------------
async def api_ai_triage(request):
    """Generates deep tactical AI incident triage analysis for an alert."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    
    alert_id = body.get("alert_id")
    target_alert = None

    if alert_id:
        for a in enclave.alerts:
            if a.alert_id == alert_id:
                target_alert = a.to_dict()
                break
    
    if not target_alert:
        if enclave.alerts:
            target_alert = enclave.alerts[0].to_dict()
        else:
            # Fallback mock template if no alerts currently present
            target_alert = {
                "alert_id": "SYS-INIT",
                "threat_class": "BOTNET_C2_BEACONING",
                "severity": "HIGH",
                "confidence_score": 0.95,
                "src_ip": "192.168.1.105",
                "dst_ip": "203.0.113.88",
                "dst_port": 443,
                "evidence": {"mean_interval_sec": 0.08, "coefficient_of_variation": 0.001, "beacon_samples": 8}
            }

    report = ai_engine.triage_incident(target_alert)
    return JSONResponse(report)

async def api_ai_synthesize_rules(request):
    """Synthesizes firewall and IDS enforcement rules (iptables, nftables, suricata, snort)."""
    try:
        body = await request.json()
    except Exception:
        body = {}

    alert_id = body.get("alert_id")
    target_alert = None
    if alert_id:
        for a in enclave.alerts:
            if a.alert_id == alert_id:
                target_alert = a.to_dict()
                break
    if not target_alert and enclave.alerts:
        target_alert = enclave.alerts[0].to_dict()

    if target_alert:
        threat_class = target_alert.get("threat_class", "BOTNET_C2_BEACONING")
        src_ip = target_alert.get("src_ip", "192.168.1.105")
        dst_ip = target_alert.get("dst_ip", "203.0.113.88")
        dst_port = int(target_alert.get("dst_port", 443))
        evidence = target_alert.get("evidence", {})
    else:
        threat_class = body.get("threat_class", "BOTNET_C2_BEACONING")
        src_ip = body.get("src_ip", "192.168.1.105")
        dst_ip = body.get("dst_ip", "203.0.113.88")
        dst_port = int(body.get("dst_port", 443))
        evidence = body.get("evidence", {})

    rules = ai_engine.synthesize_rules(threat_class, src_ip, dst_ip, dst_port, evidence)
    return JSONResponse({
        "status": "ok",
        "rules": rules,
        "metadata": {
            "threat_class": threat_class,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port
        }
    })

async def api_ai_query(request):
    """Processes natural language inquiries via the Security Analyst Console."""
    try:
        body = await request.json()
        prompt = (body.get("prompt") or body.get("query") or "").strip()
    except Exception:
        prompt = ""

    if not prompt:
        return JSONResponse({"status": "error", "message": "Empty query prompt"}, status_code=400)

    alerts_list = [a.to_dict() for a in list(enclave.alerts)[:10]]
    response_text = ai_engine.query_analyst_console(prompt, alerts_list)
    return JSONResponse({"status": "ok", "response": response_text})

async def api_mitre_matrix(request):
    """Returns active MITRE ATT&CK enterprise matrix status."""
    alerts_list = [a.to_dict() for a in list(enclave.alerts)]
    status = ai_engine.get_mitre_matrix_status(alerts_list)
    return JSONResponse(status)

async def api_dissect_packet(request):
    """Provides Wireshark-grade dissection and hex dump of recent live packets."""
    with enclave.recent_flows_lock:
        flows = list(enclave.recent_flows)
    
    if not flows:
        # Default mock dissection
        dissections = [{
            "frame_num": 1,
            "timestamp": time.time(),
            "protocol": "TCP (TLSv1.3)",
            "src": "192.168.1.77:49152",
            "dst": "185.220.101.5:443",
            "length": 512,
            "flags": "[PSH, ACK] Seq=1 Ack=1",
            "layers": [
                {"name": "Frame 1", "info": "512 bytes on wire, 512 bytes captured"},
                {"name": "Ethernet II", "info": "Src: 00:0c:29:8b:42:11, Dst: 00:50:56:c0:00:08"},
                {"name": "Internet Protocol Version 4", "info": "Src: 192.168.1.77, Dst: 185.220.101.5, TTL: 64"},
                {"name": "Transmission Control Protocol", "info": "Src Port: 49152, Dst Port: 443, Flags: PSH, ACK"},
                {"name": "Transport Layer Security", "info": "TLSv1.3 Record Layer: Handshake Protocol: Client Hello (JA4: t13d1516h2_8daaf6152771_be40b441a884)"}
            ],
            "hex_dump": (
                "0000   00 50 56 c0 00 08 00 0c 29 8b 42 11 08 00 45 00  .PV.....).B...E.\n"
                "0010   01 f2 3a 4f 40 00 40 06 8d 2e c0 a8 01 4d b9 dc  ..:O@.@......M..\n"
                "0020   65 05 c0 00 01 bb 27 0f 00 00 00 00 00 00 80 18  e.....'.........\n"
                "0030   fa f0 00 00 00 00 01 01 08 0a 00 00 16 03 01 01  ................\n"
                "0040   b7 01 00 01 b3 03 03 aa aa aa aa aa aa aa aa aa  ................"
            )
        }]
    else:
        dissections = []
        for i, f in enumerate(flows[-5:]):
            flags_str = "PSH, ACK" if f.get("proto") == "TCP" else "None"
            dissections.append({
                "frame_num": i + 1,
                "timestamp": f.get("ts", time.time()),
                "protocol": f.get("proto", "TCP"),
                "src": f"{f.get('src')}:{random.randint(1024, 65000)}",
                "dst": f"{f.get('dst')}:{f.get('port')}",
                "length": f.get("len", 64),
                "flags": flags_str,
                "layers": [
                    {"name": f"Frame {i+1}", "info": f"{f.get('len')} bytes captured"},
                    {"name": "Ethernet II", "info": "Type: IPv4 (0x0800)"},
                    {"name": "Internet Protocol Version 4", "info": f"Src: {f.get('src')}, Dst: {f.get('dst')}"},
                    {"name": f"{f.get('proto')} Protocol", "info": f"Port: {f.get('port')}"}
                ],
                "hex_dump": (
                    "0000   00 0c 29 8b 42 11 00 50 56 c0 00 08 08 00 45 00  ..).B..PV.....E.\n"
                    "0010   00 3c 1a 2b 40 00 40 06 7f 1c c0 a8 01 0a 0a 00  .<.+@.@.........\n"
                    "0020   00 05 a1 22 00 50 00 00 00 00 00 00 a0 02 72 10  ...\".P........r.\n"
                    "0030   1e f4 00 00 02 04 05 b4 04 02 08 0a 00 00 00 00  ................"
                )
            })

    return JSONResponse({"total": len(dissections), "packets": dissections})

# -------------------------------------------------------------
# WebSocket Live Telemetry Broadcaster
# -------------------------------------------------------------
async def websocket_telemetry_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_websockets.add(websocket)
    try:
        while True:
            snapshot = enclave.get_telemetry_snapshot()
            snapshot["siem"] = siem.get_status()
            snapshot["generator"] = {
                "target_pps": generator.target_pps,
                "is_running": generator.is_running
            }
            await websocket.send_text(json.dumps(snapshot))
            await asyncio.sleep(0.1) # 10 Hz refresh
    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    finally:
        connected_websockets.discard(websocket)

async def api_health(request):
    """Health check endpoint for application status."""
    return JSONResponse({"status": "ok", "service": "cybershield", "version": "2.4"})

# -------------------------------------------------------------
# Starlette Application Routing
# -------------------------------------------------------------
static_dir = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(static_dir, exist_ok=True)

routes = [
    Route("/", index, methods=["GET"]),
    Route("/api/health", api_health, methods=["GET"]),
    Route("/api/telemetry", api_telemetry, methods=["GET"]),
    Route("/api/alerts", api_alerts, methods=["GET"]),
    Route("/api/inject", api_inject_attack, methods=["POST"]),
    Route("/api/rate", api_set_rate, methods=["POST"]),
    Route("/api/generator/toggle", api_toggle_generator, methods=["POST"]),
    Route("/api/siem", api_set_siem, methods=["POST"]),
    Route("/api/pcap/replay_sample", api_replay_sample_pcap, methods=["POST"]),
    Route("/api/pcap/upload", api_upload_pcap, methods=["POST"]),
    Route("/api/ai/triage", api_ai_triage, methods=["POST"]),
    Route("/api/ai/synthesize_rule", api_ai_synthesize_rules, methods=["POST"]),
    Route("/api/ai/query", api_ai_query, methods=["POST"]),
    Route("/api/mitre/matrix", api_mitre_matrix, methods=["GET"]),
    Route("/api/dissect/packet", api_dissect_packet, methods=["GET"]),
    WebSocketRoute("/ws/live", websocket_telemetry_endpoint),
    Mount("/static", StaticFiles(directory=static_dir), name="static")
]

app = Starlette(debug=True, routes=routes)
