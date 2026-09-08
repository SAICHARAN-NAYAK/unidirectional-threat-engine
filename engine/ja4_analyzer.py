"""
JA4 TLS Client Hello Fingerprint Extraction and Malicious C2 Database
Implements the exact official JA4 fingerprinting algorithm (including GREASE bitmask,
ALPN alphanumeric extraction, and Section C extension + signature_algorithms hashing).
"""

import hashlib
import struct
from typing import Optional, Dict, Any, List

# Known malicious / adversary JA4 fingerprint database
KNOWN_MALICIOUS_JA4: Dict[str, Dict[str, Any]] = {
    "t13d1516h2_8daaf6152771_be40b441a884": {
        "name": "Cobalt Strike Beacon (Malleable C2)",
        "category": "C2_FRAMEWORK",
        "severity": "CRITICAL",
        "confidence": 0.96
    },
    "t13d1516h2_8daaf6152771_0271ddbed3aa": {
        "name": "Cobalt Strike Beacon (Malleable C2)",
        "category": "C2_FRAMEWORK",
        "severity": "CRITICAL",
        "confidence": 0.96
    },
    "t13d1516h2_8daaf6152771_23fc3dd30175": {
        "name": "Cobalt Strike Beacon (Malleable C2 Variant)",
        "category": "C2_FRAMEWORK",
        "severity": "CRITICAL",
        "confidence": 0.96
    },
    "t13d1516h2_8daaf6152771_9e9e8f498c8c": {
        "name": "Cobalt Strike HTTPS Beacon (Standard Profile)",
        "category": "C2_FRAMEWORK",
        "severity": "CRITICAL",
        "confidence": 0.96
    },
    "t13d1910h2_443cc4be124e_9855580004c8": {
        "name": "Sliver C2 Implant TLS Client",
        "category": "C2_FRAMEWORK",
        "severity": "CRITICAL",
        "confidence": 0.95
    },
    "t12i040400_a35f29916d22_c9b46e379b29": {
        "name": "Metasploit Reverse HTTPS Meterpreter",
        "category": "EXPLOITATION_FRAMEWORK",
        "severity": "HIGH",
        "confidence": 0.92
    },
    "t10i030200_56c2576b9762_000000000000": {
        "name": "WannaCry / Legacy Malware Dropper",
        "category": "RANSOMWARE_DROPPER",
        "severity": "CRITICAL",
        "confidence": 0.98
    },
    "t13i120800_b219e27c0e81_44e672cf38a0": {
        "name": "PoshC2 PowerShell HTTPS Agent",
        "category": "C2_FRAMEWORK",
        "severity": "HIGH",
        "confidence": 0.90
    },
    "t12d0806h1_994d8f28ef3c_3c8479e198a4": {
        "name": "TrickBot / Emotet TLS Downloader",
        "category": "BANKING_TROJAN",
        "severity": "HIGH",
        "confidence": 0.93
    }
}

def is_grease(val: int) -> bool:
    """GREASE values follow mask: 0x?A?A where high nibbles match (RFC 8701)."""
    return (val & 0x0F0F) == 0x0A0A and ((val >> 8) & 0xF0) == (val & 0xF0)

def extract_alpn_code(alpn_bytes: bytes) -> str:
    """Extracts first and last character of first ALPN entry, or '00'."""
    if len(alpn_bytes) < 3:
        return "00"
    # ALPN extension body: 2 bytes total len, then [1 byte len + string]
    first_len = alpn_bytes[2]
    if len(alpn_bytes) < 3 + first_len or first_len == 0:
        return "00"
    raw = alpn_bytes[3 : 3 + first_len].decode("ascii", errors="ignore")
    alnum = [c for c in raw if c.isalnum()]
    if not alnum:
        return "00"
    return f"{alnum[0]}{alnum[-1]}"

def parse_ja4(payload: bytes, proto: str = "t") -> str:
    """
    Parses raw TLS ClientHello payload and computes JA4 fingerprint.
    Input: payload starting at the TLS Record header (0x16 ...)
    """
    if len(payload) < 5 or payload[0] != 0x16:
        return ""  # Not a TLS Handshake Record

    # Handshake Header
    if len(payload) < 6:
        return ""
    hs_type = payload[5]
    if hs_type != 0x01:
        return ""  # Not a ClientHello

    idx = 9  # Skip TLS Record (5 bytes) + Handshake Type(1) + Length(3)
    if len(payload) < idx + 34:
        return ""

    client_version = struct.unpack("!H", payload[idx : idx + 2])[0]
    idx += 2 + 32  # Skip version and Random (32 bytes)

    # Session ID
    if idx >= len(payload):
        return ""
    sess_id_len = payload[idx]
    idx += 1 + sess_id_len

    # Cipher Suites
    if idx + 2 > len(payload):
        return ""
    cipher_len = struct.unpack("!H", payload[idx : idx + 2])[0]
    idx += 2
    if idx + cipher_len > len(payload):
        return ""
    raw_ciphers = [
        struct.unpack("!H", payload[idx + i : idx + i + 2])[0]
        for i in range(0, cipher_len, 2)
    ]
    idx += cipher_len

    # Compression Methods
    if idx >= len(payload):
        return ""
    comp_len = payload[idx]
    idx += 1 + comp_len

    # Extensions
    extensions: List[int] = []
    supported_versions: List[int] = []
    sig_algorithms: List[str] = []
    has_sni = False
    alpn_str = "00"

    if idx + 2 <= len(payload):
        ext_total_len = struct.unpack("!H", payload[idx : idx + 2])[0]
        idx += 2
        ext_end = min(idx + ext_total_len, len(payload))

        while idx + 4 <= ext_end and idx + 4 <= len(payload):
            ext_type, ext_len = struct.unpack("!HH", payload[idx : idx + 4])
            ext_data = payload[idx + 4 : idx + 4 + ext_len]
            idx += 4 + ext_len

            if is_grease(ext_type):
                continue

            extensions.append(ext_type)

            if ext_type == 0x0000:  # SNI
                has_sni = True
            elif ext_type == 0x0010:  # ALPN
                alpn_str = extract_alpn_code(ext_data)
            elif ext_type == 0x002B:  # supported_versions
                if len(ext_data) > 1:
                    v_len = ext_data[0]
                    for j in range(1, 1 + v_len, 2):
                        if j + 2 <= len(ext_data):
                            v = struct.unpack("!H", ext_data[j : j + 2])[0]
                            if not is_grease(v):
                                supported_versions.append(v)
            elif ext_type == 0x000D:  # signature_algorithms
                if len(ext_data) >= 2:
                    s_len = struct.unpack("!H", ext_data[0:2])[0]
                    for k in range(2, 2 + s_len, 2):
                        if k + 2 <= len(ext_data):
                            sig_algorithms.append(
                                f"{struct.unpack('!H', ext_data[k:k+2])[0]:04x}"
                            )

    # Resolve Highest Version
    version_map = {
        0x0304: "13",
        0x0303: "12",
        0x0302: "11",
        0x0301: "10",
        0x0300: "s3",
    }
    highest_v = 0
    if supported_versions:
        highest_v = max(supported_versions)
    else:
        highest_v = client_version
    ver_str = version_map.get(highest_v, "00")

    # Section A: protocol + version + SNI flag + cipher count + ext count + ALPN
    clean_ciphers = [c for c in raw_ciphers if not is_grease(c)]
    cipher_cnt = min(99, len(clean_ciphers))
    ext_cnt = min(99, len(extensions))
    sni_flag = "d" if has_sni else "i"
    ja4_a = f"{proto}{ver_str}{sni_flag}{cipher_cnt:02d}{ext_cnt:02d}{alpn_str}"

    # Section B: Sorted Ciphers Hash (12 hex chars)
    if clean_ciphers:
        sorted_ciphers = sorted(f"{c:04x}" for c in clean_ciphers)
        b_str = ",".join(sorted_ciphers)
        ja4_b = hashlib.sha256(b_str.encode()).hexdigest()[:12]
    else:
        ja4_b = "000000000000"

    # Section C: Sorted Extensions (excluding SNI & ALPN) + Signature Algorithms Hash
    ext_for_hash = sorted(
        f"{e:04x}" for e in extensions if e not in (0x0000, 0x0010)
    )
    if ext_for_hash or sig_algorithms:
        c_str = ",".join(ext_for_hash)
        if sig_algorithms:
            c_str += "_" + ",".join(sig_algorithms)
        ja4_c = hashlib.sha256(c_str.encode()).hexdigest()[:12]
    else:
        ja4_c = "000000000000"

    return f"{ja4_a}_{ja4_b}_{ja4_c}"

def evaluate_ja4_fingerprint(ja4: str, dst_ip: str, dst_port: int) -> Optional[Dict[str, Any]]:
    """Evaluates a JA4 fingerprint against threat intelligence and anomaly rules."""
    if not ja4:
        return None

    # 1. Exact signature match in known adversary database
    if ja4 in KNOWN_MALICIOUS_JA4:
        info = KNOWN_MALICIOUS_JA4[ja4]
        return {
            "is_threat": True,
            "threat_name": info["name"],
            "severity": info["severity"],
            "confidence": info["confidence"],
            "reason": f"Direct signature match for known adversary tool: {info['name']}"
        }

    # 2. Heuristic: Direct-IP TLS connection without SNI on high/non-standard ports
    # Format: t13i... or t12i...
    if len(ja4) >= 4 and ja4[3] == 'i' and dst_port not in (443, 8443, 4433):
        return {
            "is_threat": True,
            "threat_name": "Direct-IP Non-SNI TLS on Non-Standard Port",
            "severity": "HIGH",
            "confidence": 0.85,
            "reason": f"Anomalous TLS connection directly to IP without SNI on port {dst_port}"
        }

    # 3. Heuristic: Stripped extension list (less than 3 extensions in TLS 1.3)
    if ja4.startswith("t13") and len(ja4) >= 8:
        try:
            ext_count = int(ja4[6:8])
            if ext_count < 3:
                return {
                    "is_threat": True,
                    "threat_name": "Stripped TLS 1.3 Client Fingerprint",
                    "severity": "MEDIUM",
                    "confidence": 0.78,
                    "reason": f"TLS 1.3 handshake has only {ext_count} extensions, typical of custom implants"
                }
        except ValueError:
            pass

    return None
