"""
High-Throughput Synthetic Traffic Generator & Attack Vector Injector
Generates micro-batched benign flows at up to 50,000+ pkts/sec and injects synthetic cyber attacks.
"""

import time
import random
import threading
from typing import List, Optional
from .models import PacketMetadata
from .sharded_enclave import ShardedPassiveDetectionEnclave
from .ja4_analyzer import KNOWN_MALICIOUS_JA4

class TrafficGenerator:
    def __init__(self, enclave: ShardedPassiveDetectionEnclave, target_pps: int = 30000):
        self.enclave = enclave
        self.target_pps = target_pps
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        
        # IP Pools
        self.internal_ips = [f"192.168.1.{i}" for i in range(10, 120)]
        self.external_ips = [f"93.184.216.{i}" for i in range(1, 25)] + [f"104.244.42.{i}" for i in range(1, 20)]
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
        """Micro-batch burst loop with high-resolution pacing."""
        batch_size = 500
        while self.is_running:
            start_tick = time.perf_counter()
            
            # 1. Generate benign batch
            batch: List[PacketMetadata] = []
            now = time.time()
            for _ in range(batch_size):
                src = random.choice(self.internal_ips)
                dst = random.choice(self.external_ips)
                sport = random.randint(1024, 65535)
                dport = random.choice(self.common_ports)
                length = random.randint(64, 1500)
                flags = "PA" if dport != 53 else ""
                proto = "UDP" if dport == 53 else "TCP"
                batch.append(PacketMetadata(
                    timestamp=now,
                    src_ip=src,
                    dst_ip=dst,
                    src_port=sport,
                    dst_port=dport,
                    protocol=proto,
                    length=length,
                    flags=flags
                ))

            # Ingest batch
            self.enclave.ingest_batch(batch)

            # Occasional ambient attack vector (1 in 30 batches)
            if random.random() < 0.03:
                attack_type = random.choice(["BEACON", "SCAN", "SYN_FLOOD", "DGA", "JA4"])
                if attack_type == "BEACON":
                    self.inject_c2_beacon(count=7)
                elif attack_type == "SCAN":
                    self.inject_port_scan(port_count=35)
                elif attack_type == "SYN_FLOOD":
                    self.inject_syn_flood(count=150)
                elif attack_type == "DGA":
                    self.inject_dga_query(count=5)
                elif attack_type == "JA4":
                    self.inject_malicious_ja4()

            # Pacing calculation to hit target_pps
            elapsed = time.perf_counter() - start_tick
            target_batch_time = batch_size / self.target_pps
            sleep_time = target_batch_time - elapsed
            if sleep_time > 0.0005:
                time.sleep(sleep_time)

    # -------------------------------------------------------------
    # Interactive Attack Injections (Callable via UI / API)
    # -------------------------------------------------------------
    def inject_syn_flood(self, target_ip: str = "192.168.1.1", target_port: int = 80, count: int = 180):
        """Simulates distributed volumetric SYN flood to a single victim endpoint."""
        now = time.time()
        batch: List[PacketMetadata] = []
        for _ in range(count):
            spoofed_src = f"172.16.{random.randint(1, 254)}.{random.randint(1, 254)}"
            batch.append(PacketMetadata(
                timestamp=now,
                src_ip=spoofed_src,
                dst_ip=target_ip,
                src_port=random.randint(1024, 65535),
                dst_port=target_port,
                protocol="TCP",
                length=60,
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
        """Simulates high-precision periodic C2 beaconing (low CV)."""
        def _beacon_worker():
            for i in range(count):
                pkt = PacketMetadata(
                    timestamp=time.time(),
                    src_ip=bot_ip,
                    dst_ip=c2_ip,
                    src_port=54321,
                    dst_port=c2_port,
                    protocol="TCP",
                    length=128 + (i % 2) * 16,
                    flags="PA"
                )
                self.enclave.ingest_batch([pkt])
                time.sleep(interval)
        threading.Thread(target=_beacon_worker, daemon=True).start()

    def inject_port_scan(
        self,
        scanner_ip: str = "192.168.1.199",
        target_ip: str = "10.0.0.5",
        port_count: int = 40
    ):
        """Simulates rapid horizontal/vertical TCP port scan reconnaissance."""
        ports = random.sample(range(20, 2048), min(port_count, 100))
        now = time.time()
        batch: List[PacketMetadata] = []
        for p in ports:
            batch.append(PacketMetadata(
                timestamp=now,
                src_ip=scanner_ip,
                dst_ip=target_ip,
                src_port=random.randint(40000, 60000),
                dst_port=p,
                protocol="TCP",
                length=60,
                flags="S"
            ))
        self.enclave.ingest_batch(batch)

    def inject_dga_query(
        self,
        client_ip: str = "192.168.1.45",
        dns_server: str = "8.8.8.8",
        count: int = 5
    ):
        """Simulates high-entropy DGA or DNS Tunneling data exfiltration query."""
        now = time.time()
        batch: List[PacketMetadata] = []
        hex_chars = "abcdef0123456789"
        for _ in range(count):
            rand_subdomain = "".join(random.choices(hex_chars, k=random.randint(22, 32)))
            domain = f"{rand_subdomain}.malicious-c2-exfil.net"
            batch.append(PacketMetadata(
                timestamp=now,
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
            timestamp=time.time(),
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
