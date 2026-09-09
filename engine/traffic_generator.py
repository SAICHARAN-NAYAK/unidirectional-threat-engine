"""
High-Throughput Synthetic Traffic Generator & Attack Vector Injector
Generates micro-batched benign flows at up to 50,000+ pkts/sec and injects synthetic cyber attacks.
Engineered with stochastic microsecond jitter, authentic enterprise infrastructure topology,
and realistic deviant/human error events.
"""

import time
import random
import threading
from typing import List, Optional, Dict, Any
from .models import PacketMetadata, ThreatClass, ThreatSeverity
from .sharded_enclave import ShardedPassiveDetectionEnclave
from .ja4_analyzer import KNOWN_MALICIOUS_JA4

class TrafficGenerator:
    def __init__(self, enclave: ShardedPassiveDetectionEnclave, target_pps: int = 30000):
        self.enclave = enclave
        self.target_pps = target_pps
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        
        # Enterprise Infrastructure Topology
        self.infra_hosts: Dict[str, Dict[str, Any]] = {
            "192.168.1.1": {"name": "Border Gateway Firewall", "ports": [80, 443, 53, 22]},
            "192.168.1.10": {"name": "Active Directory / Kerberos DC", "ports": [53, 88, 135, 139, 389, 445, 636]},
            "192.168.1.25": {"name": "Corporate Mail Exchange", "ports": [25, 143, 587, 993, 80]},
            "192.168.1.45": {"name": "Payroll & HR Web Portal", "ports": [80, 443, 8080, 8443, 5432]},
            "192.168.1.80": {"name": "DevOps GitLab Server", "ports": [22, 80, 443, 2375, 9090]},
            "192.168.1.90": {"name": "Postgres DB Cluster", "ports": [5432, 6432]}
        }
        self.workstation_ips = [f"192.168.1.{i}" for i in range(101, 190)]
        self.external_ips = [f"93.184.216.{i}" for i in range(1, 25)] + [f"104.244.42.{i}" for i in range(1, 20)] + ["1.1.1.1", "8.8.8.8"]
        self.common_ports = [80, 443, 8080, 8443, 53, 22, 3389, 8000]

    def set_target_pps(self, pps: int):
        """Dynamically adjust target packets per second."""
        self.target_pps = max(500, min(100000, pps))

    def start(self):
        if not self.is_running:
            self.is_running = True
            self._thread = threading.Thread(target=self._run_loop, daemon=True, name="TrafficGenThread")
            self._thread.start()

    def stop(self):
        self.is_running = False
        if self._thread:
            self._thread.join(timeout=1.0)

    def _run_loop(self):
        """Micro-batch burst loop with stochastic arrival pacing and ambient enterprise chaos."""
        batch_size = 500
        iteration = 0

        while self.is_running:
            iteration += 1
            start_tick = time.perf_counter()
            now = time.time()
            
            # 1. Generate realistic benign enterprise traffic with stochastic microsecond jitter
            batch: List[PacketMetadata] = []
            for _ in range(batch_size):
                # Workstations generate outbound traffic to internet or internal infra
                if random.random() < 0.70:
                    src = random.choice(self.workstation_ips)
                    dst = random.choice(self.external_ips)
                    dport = random.choices([443, 80, 53, 8080], weights=[70, 15, 10, 5])[0]
                else:
                    # Internal workstation to server traffic
                    src = random.choice(self.workstation_ips)
                    dst = random.choice(list(self.infra_hosts.keys()))
                    dport = random.choice(self.infra_hosts[dst]["ports"])

                sport = random.randint(1024, 65535)
                length = random.randint(64, 1500)
                flags = "PA" if dport != 53 else ""
                proto = "UDP" if dport == 53 else "TCP"

                # Sub-millisecond time jitter per packet
                pkt_jitter = random.uniform(-0.004, 0.004)
                batch.append(PacketMetadata(
                    timestamp=now + pkt_jitter,
                    src_ip=src,
                    dst_ip=dst,
                    src_port=sport,
                    dst_port=dport,
                    protocol=proto,
                    length=length,
                    flags=flags
                ))

            self.enclave.ingest_batch(batch)

            # 2. Interleave authentic human enterprise chaos (1 in 15 batches)
            if iteration % 15 == 0:
                self._inject_ambient_enterprise_events()

            # 3. Occasional threat vector burst (1 in 35 batches)
            if random.random() < 0.028:
                attack_type = random.choice(["BEACON", "SCAN", "SYN_FLOOD", "DGA", "JA4"])
                if attack_type == "BEACON":
                    self.inject_c2_beacon(count=random.randint(6, 9))
                elif attack_type == "SCAN":
                    self.inject_port_scan(port_count=random.randint(28, 48))
                elif attack_type == "SYN_FLOOD":
                    self.inject_syn_flood(count=random.randint(140, 200))
                elif attack_type == "DGA":
                    self.inject_dga_query(count=random.randint(4, 7))
                elif attack_type == "JA4":
                    self.inject_malicious_ja4()

            # Pacing calculation with natural jitter to break rigid clock loops
            elapsed = time.perf_counter() - start_tick
            target_batch_time = batch_size / self.target_pps
            sleep_time = target_batch_time - elapsed + random.uniform(-0.0003, 0.0006)
            if sleep_time > 0.0005:
                time.sleep(sleep_time)

    def _inject_ambient_enterprise_events(self):
        """
        Emits authentic human/system enterprise logs (failed auth, typos, expired certs,
        script traces, benign audits) to break robotic uniformity.
        """
        event_choice = random.choice([
            "SSH_AUTH_FAIL",
            "EXPIRED_CERT",
            "DNS_TYPO",
            "USER_AGENT_ANOMALY",
            "AUDIT_TGT",
            "DEV_CRASH"
        ])

        now = time.time() - random.uniform(0.015, 0.420)
        src_ws = random.choice(self.workstation_ips)

        if event_choice == "SSH_AUTH_FAIL":
            srv = "192.168.1.80"
            conf = round(random.uniform(0.72, 0.89), 2)
            self.enclave._raise_alert(
                threat_class=ThreatClass.AUTH_FAILURE,
                severity=ThreatSeverity.MEDIUM,
                confidence=conf,
                src_ip=src_ws,
                dst_ip=f"{srv}:22",
                dst_port=22,
                evidence={
                    "service": "OpenSSH_9.2p1",
                    "failure_reason": "Invalid user credentials (3 consecutive attempts)",
                    "target_account": random.choice(["deploy_bot", "admin_svc", "root", "gitlab_runner"]),
                    "raw_syslog": f"sshd[1942]: Failed password for invalid user from {src_ws} port {random.randint(40000, 60000)} ssh2"
                }
            )
        elif event_choice == "EXPIRED_CERT":
            conf = round(random.uniform(0.85, 0.96), 2)
            self.enclave._raise_alert(
                threat_class=ThreatClass.POLICY_VIOLATION,
                severity=ThreatSeverity.LOW,
                confidence=conf,
                src_ip=src_ws,
                dst_ip="192.168.1.45:8443",
                dst_port=8443,
                evidence={
                    "certificate_subject": "CN=internal-payroll.corp.local",
                    "expiry_date": "2026-09-06T00:00:00Z (3 days expired)",
                    "issuer": "Corp-Internal-Root-CA",
                    "tls_handshake_state": "SEC_I_CONTINUE_NEEDED -> SEC_E_CERT_EXPIRED"
                }
            )
        elif event_choice == "DNS_TYPO":
            typo_domain = random.choice(["w3w.g00gle.internal", "jiraa.corp.local", "gitlab-prd.lan", "githubb.com"])
            conf = round(random.uniform(0.40, 0.65), 2)
            self.enclave._raise_alert(
                threat_class=ThreatClass.DNS_NXDOMAIN,
                severity=ThreatSeverity.INFO,
                confidence=conf,
                src_ip=src_ws,
                dst_ip="192.168.1.1:53",
                dst_port=53,
                evidence={
                    "queried_name": typo_domain,
                    "rcode": "NXDOMAIN (3 - Non-Existent Domain)",
                    "resolver": "192.168.1.1 (Gateway Unbound DNS)",
                    "note": "Typographical human operator error"
                }
            )
        elif event_choice == "USER_AGENT_ANOMALY":
            ua = random.choice([
                "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
                "python-requests/2.21.0 (unauthenticated script)",
                "curl/7.29.0 (RHEL 7 legacy automation)"
            ])
            conf = round(random.uniform(0.55, 0.78), 2)
            self.enclave._raise_alert(
                threat_class=ThreatClass.ANOMALOUS_USER_AGENT,
                severity=ThreatSeverity.LOW,
                confidence=conf,
                src_ip=src_ws,
                dst_ip="192.168.1.45:80",
                dst_port=80,
                evidence={
                    "user_agent": ua,
                    "target_uri": "/api/v1/auth/tokens",
                    "http_status": 403,
                    "anomaly": "Outdated or non-standard corporate browser profile"
                }
            )
        elif event_choice == "AUDIT_TGT":
            conf = round(random.uniform(0.92, 0.99), 2)
            self.enclave._raise_alert(
                threat_class=ThreatClass.BENIGN_AUDIT,
                severity=ThreatSeverity.INFO,
                confidence=conf,
                src_ip=src_ws,
                dst_ip="192.168.1.10:88",
                dst_port=88,
                evidence={
                    "event_id": 4768,
                    "ticket_type": "Kerberos TGT Request (KRB_AS_REQ)",
                    "account_name": f"CORP\\user_{src_ws.split('.')[-1]}",
                    "status_code": "0x0 (Success)"
                }
            )
        elif event_choice == "DEV_CRASH":
            conf = round(random.uniform(0.68, 0.84), 2)
            self.enclave._raise_alert(
                threat_class=ThreatClass.DEV_ERROR,
                severity=ThreatSeverity.LOW,
                confidence=conf,
                src_ip=src_ws,
                dst_ip="192.168.1.80:5000",
                dst_port=5000,
                evidence={
                    "service": "Internal Microservice API",
                    "stack_trace": "Traceback: ConnectionResetError: [Errno 104] Connection reset by peer in worker_thread",
                    "tcp_flags": "RST"
                }
            )

    # -------------------------------------------------------------
    # Interactive Attack Injections (Callable via UI / API)
    # -------------------------------------------------------------
    def inject_syn_flood(self, target_ip: str = "192.168.1.1", target_port: int = 80, count: int = 180):
        """Simulates distributed volumetric SYN flood with realistic botnet cluster."""
        now = time.time()
        batch: List[PacketMetadata] = []
        botnet_cluster = random.randint(10, 88)

        for idx in range(count):
            # Time jitter per packet
            pkt_time = now - random.uniform(0.01, 0.35)
            spoofed_src = f"172.16.{botnet_cluster}.{random.randint(2, 254)}"
            batch.append(PacketMetadata(
                timestamp=pkt_time,
                src_ip=spoofed_src,
                dst_ip=target_ip,
                src_port=random.randint(1024, 65535),
                dst_port=target_port,
                protocol="TCP",
                length=random.choice([54, 60, 64]),
                flags="S"
            ))
        self.enclave.ingest_batch(batch)

    def inject_c2_beacon(
        self,
        bot_ip: str = "192.168.1.105",
        c2_ip: str = "203.0.113.88",
        c2_port: int = 443,
        interval: float = 0.08,
        count: int = 8
    ):
        """Simulates periodic C2 beaconing with natural millisecond jitter."""
        def _beacon_worker():
            for i in range(count):
                # Jitter in interval
                jitter = random.uniform(-0.003, 0.003)
                pkt = PacketMetadata(
                    timestamp=time.time() - random.uniform(0.002, 0.020),
                    src_ip=bot_ip,
                    dst_ip=c2_ip,
                    src_port=54321 + (i % 3),
                    dst_port=c2_port,
                    protocol="TCP",
                    length=128 + (i % 3) * 16,
                    flags="PA"
                )
                self.enclave.ingest_batch([pkt])
                time.sleep(max(0.01, interval + jitter))
        threading.Thread(target=_beacon_worker, daemon=True).start()

    def inject_port_scan(
        self,
        scanner_ip: str = "192.168.1.199",
        target_ip: str = "10.0.0.5",
        port_count: int = 40
    ):
        """
        Simulates realistic horizontal/vertical reconnaissance probing specific internal
        enterprise targets (Payroll, DevOps, Gateway) unevenly.
        """
        now = time.time()
        batch: List[PacketMetadata] = []

        # Target selection: heavily target key internal infrastructure
        weighted_targets = [
            ("192.168.1.45", [80, 443, 8080, 8443, 5432, 3306, 8000, 21]),
            ("192.168.1.80", [22, 80, 443, 2375, 9090, 3000, 8081]),
            ("192.168.1.10", [53, 88, 135, 139, 389, 445, 636]),
            ("192.168.1.25", [25, 110, 143, 465, 587, 993]),
            ("192.168.1.102", [135, 445, 3389, 5985])
        ]

        total_probes = min(port_count, 60)
        for i in range(total_probes):
            target_tuple = random.choice(weighted_targets)
            dst_host = target_tuple[0]
            dst_port = random.choice(target_tuple[1]) if random.random() < 0.7 else random.randint(1024, 9999)

            # Random sub-second timing per probe
            pkt_time = now - random.uniform(0.01, 0.45)
            batch.append(PacketMetadata(
                timestamp=pkt_time,
                src_ip=scanner_ip,
                dst_ip=dst_host,
                src_port=random.randint(40000, 60000),
                dst_port=dst_port,
                protocol="TCP",
                length=random.choice([54, 60]),
                flags="S"
            ))

        self.enclave.ingest_batch(batch)

    def inject_dga_query(
        self,
        client_ip: str = "192.168.1.45",
        dns_server: str = "8.8.8.8",
        count: int = 5
    ):
        """Simulates high-entropy DGA exfiltration queries with realistic domain variance."""
        now = time.time()
        batch: List[PacketMetadata] = []
        hex_chars = "abcdef0123456789"

        for idx in range(count):
            pkt_time = now - random.uniform(0.01, 0.35)
            rand_subdomain = "".join(random.choices(hex_chars, k=random.randint(20, 34)))
            domain = f"{rand_subdomain}.c2-rendezvous-{random.randint(1,4)}.net"
            batch.append(PacketMetadata(
                timestamp=pkt_time,
                src_ip=client_ip,
                dst_ip=dns_server,
                src_port=random.randint(30000, 60000),
                dst_port=53,
                protocol="UDP",
                length=95 + len(domain),
                flags="",
                dns_query=domain
            ))
        self.enclave.ingest_batch(batch)

    def inject_malicious_ja4(
        self,
        client_ip: str = "192.168.1.77",
        c2_ip: str = "185.220.101.5",
        ja4_sig: Optional[str] = None
    ):
        """Injects known malicious C2 JA4 TLS client hello fingerprint."""
        chosen_ja4 = ja4_sig or random.choice(list(KNOWN_MALICIOUS_JA4.keys()))
        pkt = PacketMetadata(
            timestamp=time.time() - random.uniform(0.005, 0.050),
            src_ip=client_ip,
            dst_ip=c2_ip,
            src_port=random.randint(40000, 60000),
            dst_port=443,
            protocol="TCP",
            length=512,
            flags="PA",
            ja4=chosen_ja4
        )
        self.enclave.ingest_batch([pkt])
