"""
Generates a realistic multi-threat binary .pcap capture file for verification and testing.
Contains:
- Benign HTTP/HTTPS traffic
- High-rate SYN Flood burst
- Periodic Botnet C2 Beaconing
- Reconnaissance Port Scan
- High-Entropy DGA DNS Query
- TLS Client Hello matching Cobalt Strike JA4 fingerprint
"""

import os
import struct
import socket
import time
import random

def build_ipv4_header(src_ip: str, dst_ip: str, proto: int, payload_len: int) -> bytes:
    total_len = 20 + payload_len
    ident = random.randint(1000, 65000)
    # Version 4, IHL 5 (20 bytes)
    ver_ihl = 0x45
    tos = 0
    flags_frag = 0x4000 # Don't fragment
    ttl = 64
    checksum = 0 # Can be 0 in test pcaps
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    return struct.pack("!BBHHHBBH4s4s", ver_ihl, tos, total_len, ident, flags_frag, ttl, proto, checksum, src_bytes, dst_bytes)

def build_tcp_header(src_port: int, dst_port: int, seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    data_offset = 5 << 4 # 20 bytes
    window = 64240
    checksum = 0
    urg_ptr = 0
    hdr = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, data_offset, flags, window, checksum, urg_ptr)
    return hdr + payload

def build_udp_header(src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    checksum = 0
    return struct.pack("!HHHH", src_port, dst_port, length, checksum) + payload

def build_dns_query(domain: str) -> bytes:
    # 12-byte DNS header: Transaction ID, Flags (0x0100 standard query), Questions: 1, Answers: 0, Authority: 0, Additional: 0
    hdr = struct.pack("!HHHHHH", 0x1337, 0x0100, 1, 0, 0, 0)
    qname = b""
    for part in domain.split("."):
        qname += bytes([len(part)]) + part.encode('ascii')
    qname += b"\x00"
    # Type A (1), Class IN (1)
    qsuffix = struct.pack("!HH", 1, 1)
    return hdr + qname + qsuffix

def build_tls_client_hello_payload(sni: str = "c2.malicious-domain.com") -> bytes:
    """Builds raw TLS 1.3 Client Hello bytes producing known Cobalt Strike JA4 signature."""
    # Handshake type 1 (Client Hello)
    # Client version TLS 1.2 (0x0303) in record
    random_bytes = b"\xaa" * 32
    session_id = b"\x00" # Length 0
    
    # Cipher suites (15 ciphers)
    ciphers = [
        0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
        0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035
    ]
    cs_bytes = struct.pack(f"!H{len(ciphers)}H", len(ciphers) * 2, *ciphers)
    comp_methods = b"\x01\x00" # 1 method: NULL

    # Extensions: SNI (0x0000), Supported Versions (0x002b), ALPN (0x0010), plus 13 other standard extensions
    exts_body = b""
    
    # 1. SNI (0x0000)
    sni_bytes = sni.encode('ascii')
    sni_entry = struct.pack("!BH", 0, len(sni_bytes)) + sni_bytes
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    exts_body += struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

    # 2. Supported Versions (0x002b) -> TLS 1.3 (0x0304)
    sv_payload = struct.pack("!BH", 2, 0x0304)
    exts_body += struct.pack("!HH", 0x002b, len(sv_payload)) + sv_payload

    # 3. ALPN (0x0010) -> "h2"
    alpn_str = b"\x02h2"
    alpn_list = struct.pack("!H", len(alpn_str)) + alpn_str
    exts_body += struct.pack("!HH", 0x0010, len(alpn_list)) + alpn_list

    # Add 13 padding/dummy extensions to match 16 total extensions
    for ext_id in [0x000a, 0x000b, 0x000d, 0x0017, 0x001b, 0x0023, 0x002d, 0x0033, 0x0015, 0x0012, 0x001c, 0x001e, 0x0028]:
        exts_body += struct.pack("!HH", ext_id, 4) + b"\x00\x01\x02\x03"

    ext_total_hdr = struct.pack("!H", len(exts_body)) + exts_body

    handshake_body = struct.pack("!H", 0x0303) + random_bytes + session_id + cs_bytes + comp_methods + ext_total_hdr
    handshake_hdr = bytes([0x01]) + struct.pack("!I", len(handshake_body))[1:] # 3 bytes length
    tls_record_payload = handshake_hdr + handshake_body
    
    # TLS Record Header: 0x16 (Handshake), Version 0x0301, Length
    record_hdr = struct.pack("!BHH", 0x16, 0x0301, len(tls_record_payload))
    return record_hdr + tls_record_payload

def generate_multi_threat_pcap(filepath: str):
    """Writes a valid .pcap containing diverse threats and benign traffic."""
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    with open(filepath, "wb") as f:
        # PCAP Global Header (24 bytes)
        # Magic 0xa1b2c3d4, Major 2, Minor 4, ThisZone 0, SigFigs 0, SnapLen 65535, LinkType 1 (Ethernet)
        f.write(struct.pack("=IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

        current_ts = 1700000000.0 # Fixed reference timestamp

        def write_frame(ts, ip_pkt):
            eth_hdr = b"\x00\x0c\x29\x8b\x42\x11\x00\x50\x56\xc0\x00\x08\x08\x00" # dst MAC, src MAC, EtherType IPv4
            frame = eth_hdr + ip_pkt
            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1e6)
            pcap_pkt_hdr = struct.pack("=IIII", ts_sec, ts_usec, len(frame), len(frame))
            f.write(pcap_pkt_hdr + frame)

        # 1. Benign background traffic (200 packets)
        for i in range(200):
            current_ts += 0.002
            src = f"192.168.1.{random.randint(10, 50)}"
            dst = f"93.184.216.{random.randint(1, 10)}"
            tcp = build_tcp_header(random.randint(1024, 65000), 443, i * 100, 1000, 0x10, b"HTTP/1.1 GET /\r\n\r\n")
            ip = build_ipv4_header(src, dst, 6, len(tcp))
            write_frame(current_ts, ip + tcp)

        # 2. Attack Vector 1: Volumetric SYN Flood (180 packets to target 192.168.1.1:80)
        current_ts += 0.05
        target_ip = "192.168.1.1"
        for _ in range(180):
            current_ts += 0.0005
            spoofed_src = f"172.16.{random.randint(1, 254)}.{random.randint(1, 254)}"
            tcp = build_tcp_header(random.randint(1024, 65000), 80, random.randint(1000, 99999), 0, 0x02) # SYN
            ip = build_ipv4_header(spoofed_src, target_ip, 6, len(tcp))
            write_frame(current_ts, ip + tcp)

        # 3. Attack Vector 2: Botnet C2 Beaconing (8 periodic beacons, 0.08s interval)
        current_ts += 0.05
        bot_ip = "192.168.1.105"
        c2_ip = "203.0.113.88"
        for i in range(8):
            current_ts += 0.080 # Strictly periodic
            tcp = build_tcp_header(54321, 443, 10000 + i * 128, 20000, 0x18, b"HEARTBEAT_STATUS_OK_AGENT_007")
            ip = build_ipv4_header(bot_ip, c2_ip, 6, len(tcp))
            write_frame(current_ts, ip + tcp)

        # 4. Attack Vector 3: Port Scan Reconnaissance (40 distinct ports)
        current_ts += 0.05
        scanner_ip = "192.168.1.199"
        scan_target = "10.0.0.5"
        for port in random.sample(range(20, 1024), 40):
            current_ts += 0.001
            tcp = build_tcp_header(random.randint(40000, 60000), port, 1234, 0, 0x02)
            ip = build_ipv4_header(scanner_ip, scan_target, 6, len(tcp))
            write_frame(current_ts, ip + tcp)

        # 5. Attack Vector 4: DGA / DNS Tunneling Exfiltration
        current_ts += 0.05
        dga_domain = "f7c9e8210ba43598710ddff910a34b.tunnel-exfil-agent.net"
        dns_payload = build_dns_query(dga_domain)
        udp = build_udp_header(random.randint(30000, 60000), 53, dns_payload)
        ip = build_ipv4_header("192.168.1.45", "8.8.8.8", 17, len(udp))
        write_frame(current_ts, ip + udp)

        # 6. Attack Vector 5: Cobalt Strike TLS Handshake (JA4 signature match)
        current_ts += 0.05
        tls_payload = build_tls_client_hello_payload("beacon.threat-actor-c2.org")
        tcp = build_tcp_header(44332, 443, 9999, 1111, 0x18, tls_payload)
        ip = build_ipv4_header("192.168.1.77", "185.220.101.5", 6, len(tcp))
        write_frame(current_ts, ip + tcp)

    return os.path.abspath(filepath)

if __name__ == "__main__":
    sample_path = os.path.join(os.path.dirname(__file__), "threat_simulation.pcap")
    generate_multi_threat_pcap(sample_path)
    print(f"[+] Sample multi-threat PCAP generated: {sample_path} ({os.path.getsize(sample_path)} bytes)")
