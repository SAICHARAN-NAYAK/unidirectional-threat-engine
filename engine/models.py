"""
Core Data Models for Unidirectional IP Cyber Threat Detection Engine
Optimized with __slots__ for high-throughput, low-allocation processing.
"""

import json
import time
import uuid
from typing import Dict, Any, Optional

class ThreatSeverity:
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class ThreatClass:
    VOLUMETRIC_SYN_FLOOD = "VOLUMETRIC_SYN_FLOOD"
    BOTNET_C2_BEACONING = "BOTNET_C2_BEACONING"
    RECONNAISSANCE_SCAN = "RECONNAISSANCE_SCAN"
    DGA_OR_DNS_TUNNEL = "DGA_OR_DNS_TUNNEL"
    SUSPICIOUS_JA4_TLS = "SUSPICIOUS_JA4_TLS"
    UDP_AMPLIFICATION_FLOOD = "UDP_AMPLIFICATION_FLOOD"
    # Deviant, human error, and authentic enterprise events
    AUTH_FAILURE = "SSH_AUTH_FAILED"
    POLICY_VIOLATION = "EXPIRED_TLS_CERT"
    BENIGN_AUDIT = "SYSTEM_AUDIT_LOG"
    ANOMALOUS_USER_AGENT = "ANOMALOUS_USER_AGENT"
    DEV_ERROR = "DEV_SCRIPT_CRASH"
    DNS_NXDOMAIN = "DNS_QUERY_NXDOMAIN"

class PacketMetadata:
    __slots__ = (
        'timestamp',
        'src_ip',
        'dst_ip',
        'src_port',
        'dst_port',
        'protocol',
        'length',
        'flags',
        'dns_query',
        'ja4',
        'raw_payload'
    )

    def __init__(
        self,
        timestamp: float,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str = "TCP",
        length: int = 64,
        flags: str = "",
        dns_query: str = "",
        ja4: str = "",
        raw_payload: bytes = b""
    ):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.length = length
        self.flags = flags
        self.dns_query = dns_query
        self.ja4 = ja4
        self.raw_payload = raw_payload

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "length": self.length,
            "flags": self.flags,
            "dns_query": self.dns_query,
            "ja4": self.ja4
        }

class ThreatAlert:
    __slots__ = (
        'alert_id',
        'timestamp',
        'threat_class',
        'severity',
        'confidence_score',
        'src_ip',
        'dst_ip',
        'dst_port',
        'evidence'
    )

    def __init__(
        self,
        threat_class: str,
        severity: str,
        confidence_score: float,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        evidence: Dict[str, Any],
        alert_id: Optional[str] = None,
        timestamp: Optional[float] = None
    ):
        self.alert_id = alert_id or str(uuid.uuid4())[:8]
        self.timestamp = timestamp or time.time()
        self.threat_class = threat_class
        self.severity = severity
        self.confidence_score = round(confidence_score, 3)
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.evidence = evidence

    def to_dict(self) -> Dict[str, Any]:
        ms = int((self.timestamp % 1) * 1000)
        time_str = f"{time.strftime('%H:%M:%S', time.localtime(self.timestamp))}.{ms:03d}"
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "timestamp_str": time_str,
            "threat_class": self.threat_class,
            "severity": self.severity,
            "confidence_score": self.confidence_score,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "evidence": self.evidence
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    def to_cef(self) -> str:
        """ArcSight Common Event Format (CEF) representation for SIEM ingestion."""
        sev_map = {
            ThreatSeverity.INFO: "1",
            ThreatSeverity.LOW: "3",
            ThreatSeverity.MEDIUM: "5",
            ThreatSeverity.HIGH: "8",
            ThreatSeverity.CRITICAL: "10"
        }
        sev_num = sev_map.get(self.severity, "5")
        custom_fields = " ".join([f"cs1={k} cs1Label={v}" for k, v in list(self.evidence.items())[:2]])
        return (
            f"CEF:0|PassiveDiode|ThreatEnclave|2.0|{self.threat_class}|{self.threat_class}|{sev_num}|"
            f"src={self.src_ip} dst={self.dst_ip} dpt={self.dst_port} "
            f"cn1={self.confidence_score} cn1Label=Confidence {custom_fields}"
        )

    def to_syslog(self) -> str:
        """RFC 5424 Syslog representation."""
        t_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.timestamp))
        return f"<134>1 {t_str} passive-sensor enclave - {self.threat_class} {self.to_json()}"
