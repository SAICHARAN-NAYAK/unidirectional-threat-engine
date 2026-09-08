"""
Performance Benchmark & Threat Attribution Verification Suite
Tests sustained throughput (target: 25k - 50k+ pkts/sec) and validates detection accuracy.
"""

import time
import random
import os
import sys

# Ensure parent directory is in python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine.models import PacketMetadata, ThreatClass
from engine.sharded_enclave import ShardedPassiveDetectionEnclave
from engine.pcap_parser import replay_pcap
from samples.generate_sample_pcap import generate_multi_threat_pcap

def run_throughput_benchmark(total_packets: int = 150000, batch_size: int = 500) -> float:
    print(f"\n[*] Starting Throughput Benchmark ({total_packets:,} packets, batch size: {batch_size})...")
    enclave = ShardedPassiveDetectionEnclave(window_size=3.0, num_shards=16)

    # Pre-generate synthetic packet pool
    ips_src = [f"192.168.1.{i}" for i in range(10, 100)]
    ips_dst = [f"10.0.0.{i}" for i in range(1, 20)]
    ports = [80, 443, 8080, 53, 22]

    batches = []
    num_batches = total_packets // batch_size
    now = time.time()
    for _ in range(num_batches):
        b = []
        for _ in range(batch_size):
            b.append(PacketMetadata(
                timestamp=now,
                src_ip=random.choice(ips_src),
                dst_ip=random.choice(ips_dst),
                src_port=random.randint(1024, 65000),
                dst_port=random.choice(ports),
                protocol="TCP",
                length=random.randint(64, 1500),
                flags="PA"
            ))
        batches.append(b)

    # Measure ingestion speed
    start_time = time.perf_counter()
    for b in batches:
        enclave.ingest_batch(b)
    elapsed = time.perf_counter() - start_time

    rate_pps = total_packets / elapsed
    mbps = (enclave.total_bytes_processed * 8) / (elapsed * 1_000_000)

    print(f"[+] Ingested {total_packets:,} packets in {elapsed:.3f}s")
    print(f"[+] Sustained Ingest Rate: {rate_pps:,.0f} pkts/sec | Throughput: {mbps:.2f} Mbps")
    
    # Measure evaluation latency
    eval_start = time.perf_counter()
    enclave.prune_and_evaluate()
    eval_latency = (time.perf_counter() - eval_start) * 1000.0
    print(f"[+] Full Sliding Window Prune & Evaluation Latency: {eval_latency:.3f} ms")

    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')

    assert rate_pps >= 25000, f"Throughput {rate_pps:,.0f} pps is below target 25,000 pps!"
    print(f"[PASS] THROUGHPUT TARGET MET: {rate_pps:,.0f} pkts/sec >= 25,000 target.")
    return rate_pps

def run_detection_validation():
    print(f"\n[*] Starting Threat Detection & Attribution Accuracy Test...")
    pcap_path = os.path.join(os.path.dirname(__file__), "samples", "threat_simulation.pcap")
    if not os.path.exists(pcap_path):
        generate_multi_threat_pcap(pcap_path)

    enclave = ShardedPassiveDetectionEnclave(window_size=15.0, num_shards=16)

    # Replay PCAP
    replayed = replay_pcap(enclave, pcap_path, batch_size=100, speed_multiplier=0.0)
    print(f"[+] Replayed {replayed} packets from {os.path.basename(pcap_path)}")

    # Run evaluation
    enclave.prune_and_evaluate()

    detected_classes = {a.threat_class for a in enclave.alerts}
    print(f"[+] Detected {len(enclave.alerts)} threat alerts across classes:")
    for a in enclave.alerts:
        print(f"    - [{a.severity:<8}] {a.threat_class:<26} Conf: {a.confidence_score:.2f} Target: {a.src_ip} -> {a.dst_ip}:{a.dst_port}")

    expected_threats = [
        ThreatClass.VOLUMETRIC_SYN_FLOOD,
        ThreatClass.BOTNET_C2_BEACONING,
        ThreatClass.RECONNAISSANCE_SCAN,
        ThreatClass.DGA_OR_DNS_TUNNEL,
        ThreatClass.SUSPICIOUS_JA4_TLS
    ]

    missing = []
    for et in expected_threats:
        if et in detected_classes:
            print(f"    [PASS] Confirmed Detection: {et}")
        else:
            missing.append(et)
            print(f"    [FAIL] MISSING DETECTION: {et}")

    if missing:
        raise AssertionError(f"Missing expected detections: {missing}")
    print(f"[PASS] ALL THREAT VECTORS VALIDATED SUCCESSFULLY (5/5).")

if __name__ == "__main__":
    pps = run_throughput_benchmark(total_packets=150000, batch_size=500)
    run_detection_validation()
    print("\n[SUCCESS] All benchmarks and detection validations passed!")
