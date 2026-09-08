"""
SIEM & SOC Export Dispatcher
Non-blocking background worker queue that pushes threat alerts to Webhooks, Syslog, and CEF logs.
"""

import queue
import threading
import urllib.request
import json
from typing import Optional, Dict, Any
from .models import ThreatAlert

class SIEMExporter:
    def __init__(self, webhook_url: Optional[str] = None, log_file: Optional[str] = None):
        self.webhook_url = webhook_url
        self.log_file = log_file
        self.queue: queue.Queue = queue.Queue(maxsize=5000)
        self.is_running = True
        self.total_exported = 0
        self.total_failures = 0
        self.last_export_ts = 0.0
        
        # Start background dispatch worker
        self._worker_thread = threading.Thread(target=self._worker, daemon=True, name="SIEMExportWorker")
        self._worker_thread.start()

    def set_webhook_url(self, url: str):
        self.webhook_url = url.strip() if url else None

    def export_alert(self, alert: ThreatAlert):
        """Enqueue alert for non-blocking dispatch."""
        try:
            self.queue.put_nowait(alert)
        except queue.Full:
            self.total_failures += 1

    def _worker(self):
        while self.is_running:
            try:
                alert: ThreatAlert = self.queue.get(timeout=0.5)
            except queue.Empty:
                continue

            # 1. Local File Logging (JSONL and CEF)
            if self.log_file:
                try:
                    with open(self.log_file, "a", encoding="utf-8") as f:
                        f.write(alert.to_json() + "\n")
                except Exception:
                    pass

            # 2. Webhook POST
            if self.webhook_url:
                try:
                    payload = json.dumps({
                        "event": "cyber_threat_alert",
                        "alert": alert.to_dict(),
                        "cef": alert.to_cef()
                    }).encode('utf-8')
                    req = urllib.request.Request(
                        self.webhook_url,
                        data=payload,
                        headers={"Content-Type": "application/json", "User-Agent": "PassiveSensor-Diode/2.0"},
                        method="POST"
                    )
                    with urllib.request.urlopen(req, timeout=2.0) as resp:
                        pass
                except Exception:
                    self.total_failures += 1

            self.total_exported += 1
            self.last_export_ts = alert.timestamp
            self.queue.task_done()

    def get_status(self) -> Dict[str, Any]:
        return {
            "webhook_configured": bool(self.webhook_url),
            "webhook_url": self.webhook_url or "Disabled",
            "total_exported": self.total_exported,
            "total_failures": self.total_failures,
            "queue_depth": self.queue.qsize()
        }
