"""
CYBERSHIELD // Enterprise Security Operations & Autonomous Threat Enclave
Desktop Application Mode Launcher

Launches the Threat Detection Enclave as a standalone native desktop application
without browser address bars or navigation elements.
Modelled after CrowdStrike Falcon, Palo Alto Cortex XDR, and Splunk Enterprise Security.
"""

import sys
import os
import time
import socket
import threading
import subprocess
import webbrowser
import urllib.request
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(('127.0.0.1', port)) == 0

def find_available_port(start_port: int = 8080) -> int:
    port = start_port
    while is_port_in_use(port) and port < start_port + 10:
        # Check if the existing service is already our Cybershield engine
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{port}/api/health", headers={'User-Agent': 'CybershieldApp/2.4'})
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                if data.get("status") == "ok":
                    return port
        except Exception:
            port += 1
    return port

def run_backend_server(host: str, port: int):
    """Starts the Uvicorn ASGI engine in a daemon thread."""
    import uvicorn
    from web.server import app
    uvicorn.run(app, host=host, port=port, log_level="warning")

def find_browser_app_executable() -> str | None:
    """Finds Edge, Chrome, or Brave executable on Windows for native --app mode."""
    candidates = [
        # Microsoft Edge (standard on all Windows 10/11)
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\Application\msedge.exe"),
        # Google Chrome
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
        # Brave
        r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
    ]
    for p in candidates:
        if os.path.isfile(p):
            return p
    return None

def wait_for_server(url: str, timeout: float = 12.0) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        try:
            req = urllib.request.Request(f"{url}/api/health", headers={'User-Agent': 'CybershieldApp/2.4'})
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.3)
    return False

def main():
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')

    print("=" * 80)
    print(" CYBERSHIELD // ENTERPRISE THREAT ENCLAVE & SECURITY OPERATIONS PLATFORM")
    print(" [Application Mode] Launching Hardened Enterprise SOC Console...")
    print("=" * 80)

    host = "127.0.0.1"
    port = 8080

    # If port is in use and already running Cybershield, we reuse it; otherwise find port or launch
    server_already_running = False
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/health", headers={'User-Agent': 'CybershieldApp/2.4'})
        with urllib.request.urlopen(req, timeout=1.0) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            if data.get("status") == "ok":
                server_already_running = True
    except Exception:
        server_already_running = False

    if not server_already_running:
        if is_port_in_use(port):
            port = find_available_port(8081)
        
        print(f"[+] Starting Unidirectional Threat Engine & Server on http://{host}:{port}...")
        server_thread = threading.Thread(target=run_backend_server, args=(host, port), daemon=True)
        server_thread.start()

        app_url = f"http://{host}:{port}"
        print(f"[+] Awaiting engine initialization at {app_url}...")
        if not wait_for_server(app_url, timeout=15.0):
            print("[!] Warning: Server initialization timed out. Attempting to launch anyway...")
    else:
        app_url = f"http://127.0.0.1:{port}"
        print(f"[+] Active Cybershield Sensor Engine detected on {app_url}")

    browser_bin = find_browser_app_executable()

    if browser_bin:
        print(f"[+] Spawning Native Standalone Application Window via: {os.path.basename(browser_bin)}")
        # Profile directory in scratch
        user_data_dir = os.path.join(BASE_DIR, ".app_profile")
        cmd = [
            browser_bin,
            f"--app={app_url}",
            f"--window-size=1600,980",
            f"--user-data-dir={user_data_dir}",
            "--disable-extensions",
            "--disable-plugins",
            "--app-id=CybershieldThreatEnclave",
            "--new-window"
        ]
        try:
            process = subprocess.Popen(cmd)
            print(f"[+] Application running with PID: {process.pid}")
            print("[+] Keep this console open while using the application. Press Ctrl+C to stop.")
            process.wait()
            print("[+] Application window closed.")
        except KeyboardInterrupt:
            print("\n[+] Shutting down Cybershield Application...")
            if process:
                process.terminate()
        except Exception as e:
            print(f"[!] Error launching browser app mode: {e}. Falling back to default browser...")
            webbrowser.open(app_url)
    else:
        print(f"[+] Opening standard browser interface at {app_url}...")
        webbrowser.open(app_url)

if __name__ == "__main__":
    main()
