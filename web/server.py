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

# Global Engine Singleton Instances
enclave = ShardedPassiveDetectionEnclave(window_size=3.0, num_shards=16)
generator = TrafficGenerator(enclave, target_pps=30000)
siem = SIEMExporter(log_file=os.path.join(BASE_DIR, "threat_alerts.jsonl"))
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
        if batch:
            enclave.ingest_batch(batch)
            count += len(batch)

        enclave.prune_and_evaluate()
        return JSONResponse({"status": "ok", "processed_packets": count, "filename": pcap_file.filename})
    except Exception as e:
        return JSONResponse({"status": "error", "message": f"Error parsing PCAP: {str(e)}"}, status_code=500)

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

# -------------------------------------------------------------
# Starlette Application Routing
# -------------------------------------------------------------
static_dir = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(static_dir, exist_ok=True)

routes = [
    Route("/", index, methods=["GET"]),
    Route("/api/telemetry", api_telemetry, methods=["GET"]),
    Route("/api/alerts", api_alerts, methods=["GET"]),
    Route("/api/inject", api_inject_attack, methods=["POST"]),
    Route("/api/rate", api_set_rate, methods=["POST"]),
    Route("/api/generator/toggle", api_toggle_generator, methods=["POST"]),
    Route("/api/siem", api_set_siem, methods=["POST"]),
    Route("/api/pcap/replay_sample", api_replay_sample_pcap, methods=["POST"]),
    Route("/api/pcap/upload", api_upload_pcap, methods=["POST"]),
    WebSocketRoute("/ws/live", websocket_telemetry_endpoint),
    Mount("/static", StaticFiles(directory=static_dir), name="static")
]

app = Starlette(debug=True, routes=routes)
