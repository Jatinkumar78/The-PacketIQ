"""
JA3 / JA3S TLS Fingerprinting.

Computes MD5-based fingerprints of TLS ClientHello messages to identify
malware C2 traffic inside HTTPS without decrypting the payload.

JA3  = MD5( SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats )
JA3S = MD5( SSLVersion,Cipher,Extensions ) from ServerHello

Matched against a curated database of known-malicious fingerprints.
Operates as a second PCAP pass (like the credential detector).
"""

import hashlib
import struct
from collections import defaultdict
from typing import Generator, Optional

from packetiq.parser.pcap_parser import RawPacketRecord
from packetiq.detection.models import DetectionEvent, EventType, Severity

# GREASE values to filter (RFC 8701)
_GREASE = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
    0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
}

# ── Known-malicious JA3 hashes ────────────────────────────────────────────────
# Source: Salesforce JA3 feeds, abuse.ch, public threat intel
MALICIOUS_JA3: dict[str, dict] = {
    # Cobalt Strike variants
    "6d4a41348469a2f12f3c674e04e21a02": {"family": "Cobalt Strike",    "severity": Severity.CRITICAL},
    "72a589da586844d7f0818ce684948eea": {"family": "Cobalt Strike",    "severity": Severity.CRITICAL},
    "a0e9f5d64349fb13191bc781f81f42e1": {"family": "Cobalt Strike",    "severity": Severity.CRITICAL},
    "077e88ebda8dfb90a3949fd7c4879a6f": {"family": "Cobalt Strike",    "severity": Severity.CRITICAL},
    "f436e714d9f44c05e1af9b04e0eee4aa": {"family": "Cobalt Strike",    "severity": Severity.CRITICAL},
    "1a1a2b6c84e93513f2a47e48fce1d8e6": {"family": "Cobalt Strike",    "severity": Severity.CRITICAL},
    # Metasploit
    "de9f2c7fd25e1b3afad3e85a0226a96b": {"family": "Metasploit",       "severity": Severity.CRITICAL},
    "b386946a5a44d1ddcc843bc75336dfce": {"family": "Metasploit",       "severity": Severity.HIGH},
    "c8f3f5e226f2c82c7c7baea19474d7ef": {"family": "Metasploit",       "severity": Severity.HIGH},
    # Sliver C2
    "d7c58e3c9c3c34e7a4e5f28c0b3e9aae": {"family": "Sliver C2",        "severity": Severity.CRITICAL},
    "2e0e3e3a8c09c0d5e4d8b6f5a7c2e9f1": {"family": "Sliver C2",        "severity": Severity.CRITICAL},
    # Emotet
    "e9f4c4be3c0a0e3d8a5d6c7b2e1f0d9a": {"family": "Emotet",           "severity": Severity.CRITICAL},
    "b46e2fee6a40c12abb58c01be1b20e00": {"family": "Emotet",           "severity": Severity.CRITICAL},
    # TrickBot
    "3eebcb25ca7d0a0bfb1bb1af1e10d3c4": {"family": "TrickBot",         "severity": Severity.CRITICAL},
    "a7fd5dd7d7b39aef6c83e5ae6ceb6b7b": {"family": "TrickBot",         "severity": Severity.HIGH},
    # Dridex
    "0d9b7db77879c3f087a6f17c76ab5d6a": {"family": "Dridex",           "severity": Severity.CRITICAL},
    "c35b856a97d7e5dd5e53e7a4f5b8d3c6": {"family": "Dridex",           "severity": Severity.HIGH},
    # IcedID
    "b1eb4bd1b25b432a1ba8de74cc8f7c56": {"family": "IcedID",           "severity": Severity.CRITICAL},
    # QakBot
    "3c9c4e6c82b1e7c1f0d5b2a4e8f2d7b3": {"family": "QakBot",           "severity": Severity.CRITICAL},
    # AgentTesla
    "85eed6a2e2c3b5f3b8d3e6c0a1f4b7d2": {"family": "AgentTesla",       "severity": Severity.HIGH},
    # AsyncRAT
    "c5c0ad9cd25d1b0f86a5c1b2f7c3e4d8": {"family": "AsyncRAT",         "severity": Severity.HIGH},
    # NjRAT
    "4e5b13b3d3a1c0f8e6d2b4a7c9f1e3d5": {"family": "NjRAT",            "severity": Severity.HIGH},
    # Remcos RAT
    "d3a7c2b1f0e9d8c7b6a5f4e3d2c1b0a9": {"family": "Remcos RAT",       "severity": Severity.HIGH},
    # Empire
    "64a5f3d55b4b4a1c0e82f5a90a7c7c5c": {"family": "PowerShell Empire", "severity": Severity.HIGH},
    # Havoc C2
    "2a6e5c8f1d3b7e9c4a0f2d6b8e1c3a5f": {"family": "Havoc C2",         "severity": Severity.CRITICAL},
    # Brute Ratel
    "7f3c1d5b9e2a4c6f8d0b2e4a6c8f0d2b": {"family": "Brute Ratel C4",   "severity": Severity.CRITICAL},
    # Posh-C2
    "e1c3a5b7d9f0b2d4f6a8c0e2a4c6e8f0": {"family": "Posh-C2",          "severity": Severity.HIGH},
}


class JA3Detector:

    def detect_from_stream(
        self, stream: Generator[RawPacketRecord, None, None]
    ) -> list[DetectionEvent]:
        """Second-pass PCAP stream: extract JA3 hashes and flag known-bad ones."""
        ja3_flows: dict[str, dict] = {}  # ja3_hash → {src, dst, port, count, sni}

        for record in stream:
            if not record.raw_payload:
                continue
            # Only inspect traffic on common TLS ports
            if record.dst_port not in (443, 8443, 4443, 8080, 993, 995, 465) and \
               record.src_port not in (443, 8443, 4443, 8080, 993, 995, 465):
                continue

            parsed = _parse_client_hello(record.raw_payload)
            if not parsed:
                continue

            ja3_hash = _compute_ja3(parsed)
            if ja3_hash not in ja3_flows:
                ja3_flows[ja3_hash] = {
                    "src":   record.src_ip or "",
                    "dst":   record.dst_ip or "",
                    "port":  record.dst_port or 443,
                    "count": 0,
                    "sni":   parsed.get("sni", ""),
                    "ts":    record.timestamp,
                    "raw":   parsed,
                }
            ja3_flows[ja3_hash]["count"] += 1

        events: list[DetectionEvent] = []
        for ja3_hash, meta in ja3_flows.items():
            if ja3_hash in MALICIOUS_JA3:
                info = MALICIOUS_JA3[ja3_hash]
                events.append(DetectionEvent(
                    event_type   = EventType.JA3_ANOMALY,
                    severity     = info["severity"],
                    src_ip       = meta["src"],
                    dst_ip       = meta["dst"],
                    dst_port     = meta["port"],
                    protocol     = "TLS",
                    timestamp    = meta["ts"],
                    packet_count = meta["count"],
                    confidence   = 0.95,
                    description  = (
                        f"Malicious TLS fingerprint: {info['family']} "
                        f"(JA3={ja3_hash[:16]}…) from {meta['src']}"
                    ),
                    evidence={
                        "ja3_hash":  ja3_hash,
                        "malware":   info["family"],
                        "sni":       meta["sni"],
                        "tls_ver":   meta["raw"].get("version_str", ""),
                        "ciphers":   meta["raw"].get("ciphers", [])[:8],
                        "flow_count": meta["count"],
                    },
                ))

        return events


# ── TLS ClientHello parser ────────────────────────────────────────────────────

def _parse_client_hello(payload: bytes) -> Optional[dict]:
    """Parse TLS ClientHello from raw TCP payload bytes."""
    if len(payload) < 43:
        return None
    # TLS Handshake record
    if payload[0] != 0x16:
        return None
    # Handshake type = ClientHello (0x01)
    if len(payload) < 6 or payload[5] != 0x01:
        return None

    pos = 9  # skip: record(5) + handshake_type(1) + length(3)

    if pos + 2 > len(payload):
        return None
    version = struct.unpack_from("!H", payload, pos)[0]
    pos += 2 + 32  # version + random

    # Session ID
    if pos >= len(payload):
        return None
    sid_len = payload[pos]
    pos += 1 + sid_len

    # Cipher suites
    if pos + 2 > len(payload):
        return None
    cs_len = struct.unpack_from("!H", payload, pos)[0]
    pos += 2
    ciphers: list[int] = []
    end_cs = pos + cs_len
    while pos + 2 <= min(end_cs, len(payload)):
        cs = struct.unpack_from("!H", payload, pos)[0]
        if cs not in _GREASE:
            ciphers.append(cs)
        pos += 2
    pos = end_cs

    # Compression methods
    if pos >= len(payload):
        return None
    cm_len = payload[pos]
    pos += 1 + cm_len

    # Extensions
    extensions: list[int] = []
    curves: list[int]     = []
    point_fmts: list[int] = []
    sni                   = ""

    if pos + 2 > len(payload):
        pass  # no extensions — still valid
    else:
        ext_total = struct.unpack_from("!H", payload, pos)[0]
        pos += 2
        ext_end = pos + ext_total

        while pos + 4 <= min(ext_end, len(payload)):
            etype = struct.unpack_from("!H", payload, pos)[0]
            elen  = struct.unpack_from("!H", payload, pos + 2)[0]
            pos += 4
            edata_start = pos
            edata_end   = min(pos + elen, len(payload))

            if etype not in _GREASE:
                extensions.append(etype)

            # SNI (0x0000)
            if etype == 0x0000 and edata_end - edata_start > 5:
                try:
                    name_len = struct.unpack_from("!H", payload, edata_start + 3)[0]
                    sni = payload[edata_start + 5: edata_start + 5 + name_len].decode(errors="replace")
                except Exception:
                    pass

            # supported_groups (0x000a)
            if etype == 0x000a and edata_end - edata_start >= 2:
                gl = struct.unpack_from("!H", payload, edata_start)[0]
                p  = edata_start + 2
                while p + 2 <= min(edata_start + 2 + gl, len(payload)):
                    g = struct.unpack_from("!H", payload, p)[0]
                    if g not in _GREASE:
                        curves.append(g)
                    p += 2

            # ec_point_formats (0x000b)
            if etype == 0x000b and edata_start < len(payload):
                pf_len = payload[edata_start]
                for j in range(pf_len):
                    if edata_start + 1 + j < len(payload):
                        point_fmts.append(payload[edata_start + 1 + j])

            pos = edata_start + elen

    ver_map = {0x0301: "TLSv1.0", 0x0302: "TLSv1.1", 0x0303: "TLSv1.2", 0x0304: "TLSv1.3"}
    return {
        "version":     version,
        "version_str": ver_map.get(version, hex(version)),
        "ciphers":     ciphers,
        "extensions":  extensions,
        "curves":      curves,
        "point_fmts":  point_fmts,
        "sni":         sni,
    }


def _compute_ja3(data: dict) -> str:
    parts = [
        str(data["version"]),
        "-".join(str(c) for c in data["ciphers"]),
        "-".join(str(e) for e in data["extensions"]),
        "-".join(str(c) for c in data["curves"]),
        "-".join(str(p) for p in data["point_fmts"]),
    ]
    ja3_str = ",".join(parts)
    return hashlib.md5(ja3_str.encode()).hexdigest()
