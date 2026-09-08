"""
Zero-Dependency Binary PCAP File Parser and Streaming Replay Engine
Parses standard .pcap captures (Ethernet II, IPv4, TCP, UDP, DNS, TLS Client Hello) into PacketMetadata.
"""

import os
import struct
import socket
import time
from typing import Iterator, Optional, Tuple
from .models import PacketMetadata
from .ja4_analyzer import parse_ja4

PCAP_MAGIC_SAME = 0xa1b2c3d4
PCAP_MAGIC_SWAP = 0xd4c3b2a1
PCAP_MAGIC_NANO_SAME = 0xa1b23c4d
PCAP_MAGIC_NANO_SWAP = 0x4d3cb2a1

def _parse_dns_query(payload: bytes) -> str:
    """Parses DNS Question QNAME from UDP DNS payload."""
    if len(payload) < 12:
        return ""
    # DNS header is 12 bytes
    qdcount = struct.unpack("!H", payload[4:6])[0]
    if qdcount == 0:
        return ""

    offset = 12
    labels = []
    while offset < len(payload):
        length = payload[offset]
        if length == 0:
            break
        # Pointer check (compression)
        if (length & 0xC0) == 0xC0:
            break
        offset += 1
        if offset + length > len(payload):
            break
        label = payload[offset:offset+length].decode('ascii', errors='ignore')
        labels.append(label)
        offset += length

    return ".".join(labels)

def _parse_tcp_flags(flag_byte: int) -> str:
    """Extracts standard TCP flags as string characters."""
    flags = []
    if flag_byte & 0x01: flags.append("F") # FIN
    if flag_byte & 0x02: flags.append("S") # SYN
    if flag_byte & 0x04: flags.append("R") # RST
    if flag_byte & 0x08: flags.append("P") # PSH
    if flag_byte & 0x10: flags.append("A") # ACK
    if flag_byte & 0x20: flags.append("U") # URG
    return "".join(flags)

def parse_pcap_stream(stream) -> Iterator[PacketMetadata]:
    """Parses binary PCAP byte stream and yields PacketMetadata instances."""
    # Global Header (24 bytes)
    global_hdr = stream.read(24)
    if len(global_hdr) < 24:
        return

    magic = struct.unpack("!I", global_hdr[0:4])[0]
    endian = "!"
    is_nano = False

    if magic == 0xa1b2c3d4:
        endian = ">"
    elif magic == 0xd4c3b2a1:
        endian = "<"
    elif magic == 0xa1b23c4d:
        endian = ">"
        is_nano = True
    elif magic == 0x4d3cb2a1:
        endian = "<"
        is_nano = True
    else:
        # Try host endianness fallback
        magic_host = struct.unpack("=I", global_hdr[0:4])[0]
        if magic_host == PCAP_MAGIC_SAME:
            endian = "="
        else:
            return

    linktype = struct.unpack(f"{endian}I", global_hdr[20:24])[0]
    # LinkType 1 = Ethernet, 113 = Linux Cooked (SLL)
    eth_offset = 14 if linktype == 1 else (16 if linktype == 113 else 14)

    # Per-packet record parsing
    while True:
        pkt_hdr = stream.read(16)
        if len(pkt_hdr) < 16:
            break

        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(f"{endian}IIII", pkt_hdr)
        ts = ts_sec + (ts_frac / 1e9 if is_nano else ts_frac / 1e6)

        pkt_data = stream.read(incl_len)
        if len(pkt_data) < incl_len:
            break

        if len(pkt_data) < eth_offset + 20:
            continue

        # Check EtherType (IPv4 = 0x0800)
        eth_type = struct.unpack("!H", pkt_data[12:14])[0] if linktype == 1 else 0x0800
        if eth_type != 0x0800:
            continue

        # IPv4 Header
        ip_data = pkt_data[eth_offset:]
        if len(ip_data) < 20:
            continue

        ihl = (ip_data[0] & 0x0F) * 4
        if len(ip_data) < ihl:
            continue

        proto_num = ip_data[9]
        src_ip = socket.inet_ntoa(ip_data[12:16])
        dst_ip = socket.inet_ntoa(ip_data[16:20])

        transport_data = ip_data[ihl:]
        proto = "TCP" if proto_num == 6 else ("UDP" if proto_num == 17 else "OTHER")
        sport, dport = 0, 0
        flags = ""
        dns_query = ""
        ja4 = ""

        if proto == "TCP" and len(transport_data) >= 20:
            sport, dport = struct.unpack("!HH", transport_data[0:4])
            tcp_offset = ((transport_data[12] >> 4) & 0x0F) * 4
            flags = _parse_tcp_flags(transport_data[13])
            payload = transport_data[tcp_offset:] if len(transport_data) > tcp_offset else b""

            # Inspect TLS Client Hello for JA4
            if payload and payload[0] == 0x16:
                ja4 = parse_ja4(payload, proto="t")

        elif proto == "UDP" and len(transport_data) >= 8:
            sport, dport = struct.unpack("!HH", transport_data[0:4])
            payload = transport_data[8:]
            if dport == 53 or sport == 53:
                dns_query = _parse_dns_query(payload)

        yield PacketMetadata(
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=sport,
            dst_port=dport,
            protocol=proto,
            length=incl_len,
            flags=flags,
            dns_query=dns_query,
            ja4=ja4,
            raw_payload=pkt_data[:128]
        )

def parse_pcap_file(filepath: str) -> Iterator[PacketMetadata]:
    """Opens a .pcap file and yields PacketMetadata."""
    with open(filepath, "rb") as f:
        yield from parse_pcap_stream(f)

def replay_pcap(enclave, filepath: str, batch_size: int = 500, speed_multiplier: float = 0.0):
    """
    Replays a PCAP file into the threat enclave.
    If speed_multiplier == 0.0, replays at maximum line-rate throughput.
    """
    batch = []
    total_replayed = 0
    start_wall = time.time()
    first_pcap_ts = None

    for pkt in parse_pcap_file(filepath):
        if first_pcap_ts is None:
            first_pcap_ts = pkt.timestamp

        batch.append(pkt)
        if len(batch) >= batch_size:
            enclave.ingest_batch(batch)
            total_replayed += len(batch)
            batch = []

            if speed_multiplier > 0.0 and first_pcap_ts:
                pcap_elapsed = (pkt.timestamp - first_pcap_ts) / speed_multiplier
                wall_elapsed = time.time() - start_wall
                diff = pcap_elapsed - wall_elapsed
                if diff > 0.001:
                    time.sleep(min(diff, 0.1))

    if batch:
        enclave.ingest_batch(batch)
        total_replayed += len(batch)

    return total_replayed
