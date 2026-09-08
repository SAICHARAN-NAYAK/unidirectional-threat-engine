"""
Launcher for Unidirectional IP Cyber Threat Detection Engine & Web SOC Dashboard
Target Throughput: 25,000 - 50,000+ flows/sec.
Starts Uvicorn ASGI web server on http://127.0.0.1:8080.
"""

import sys
import os
import uvicorn
import socket

# Add current directory to path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0

def find_available_port(start_port: int = 8080) -> int:
    port = start_port
    while is_port_in_use(port) and port < start_port + 10:
        port += 1
    return port

if __name__ == "__main__":
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')

    host = os.getenv("HOST", "0.0.0.0")
    env_port = os.getenv("PORT")
    port = int(env_port) if env_port else find_available_port(8080)
    
    print("=" * 80)
    print(" CYBERSHIELD // UNIDIRECTIONAL PASSIVE NETWORK THREAT SENSOR ENCLAVE")
    print(" Architecture: 16-Shard Hash Partitioning | Target Rate: 25,000 - 50,000+ pps")
    print(f" Web SOC Operations Dashboard: http://{host}:{port}")
    print(f" Air-Gap Status: UNIDIRECTIONAL RX ONLY (Optical Diode Mode)")
    print("=" * 80)

    from web.server import app
    uvicorn.run(app, host=host, port=port, log_level="info")
