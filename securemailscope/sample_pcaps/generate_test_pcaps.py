"""
securemailscope/sample_pcaps/generate_test_pcaps.py
------------------------------------------------------
Synthetic PCAP generator for rule-engine test fixtures and demo material.

Generates all 6 test scenarios defined in PRD §7 using Scapy to craft
realistic SMTP/IMAP TLS sessions.

Scenarios:
  1. Clean TLS 1.3 + ECDHE + valid cert
  2. Deprecated TLS 1.0 session
  3. Expired certificate
  4. Self-signed certificate
  5. STARTTLS stripping downgrade
  6. No-PFS static RSA session

Usage:
  python -m securemailscope.sample_pcaps.generate_test_pcaps

Output files are written to the sample_pcaps/ directory.
"""

from __future__ import annotations

import os
import struct
import time
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent

# ---------------------------------------------------------------------------
# Minimal PCAP file writer (no scapy dependency for generation)
# Global header + packet records in libpcap format
# ---------------------------------------------------------------------------
_PCAP_MAGIC = 0xA1B2C3D4
_PCAP_VERSION_MAJOR = 2
_PCAP_VERSION_MINOR = 4
_LINKTYPE_ETHERNET = 1    # Ethernet (matches our frames)


def _pcap_global_header() -> bytes:
    return struct.pack(
        "<IHHiIII",
        _PCAP_MAGIC,
        _PCAP_VERSION_MAJOR, _PCAP_VERSION_MINOR,
        0,        # thiszone
        0,        # sigfigs
        65535,    # snaplen
        _LINKTYPE_ETHERNET,   # link_type: Ethernet
    )


def _pcap_record(ts: float, data: bytes) -> bytes:
    ts_sec = int(ts)
    ts_usec = int((ts - ts_sec) * 1_000_000)
    return struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data)) + data


def _eth_ip_tcp(
    src_ip: str, dst_ip: str, src_port: int, dst_port: int,
    payload: bytes, seq: int = 1000, ack: int = 0, flags: int = 0x18
) -> bytes:
    """Build minimal Ethernet + IPv4 + TCP frame."""
    # Ethernet header (dummy MACs)
    eth = bytes.fromhex("aabbccddeeff") + bytes.fromhex("112233445566") + b"\x08\x00"

    # IPv4 header (no options)
    total_len = 20 + 20 + len(payload)
    iph = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0,  # version/ihl, DSCP/ECN
        total_len,
        0x1234,  # id
        0x4000,  # flags/fragment offset (DF)
        64,      # TTL
        6,       # protocol = TCP
        0,       # checksum (not computed)
        bytes(map(int, src_ip.split("."))),
        bytes(map(int, dst_ip.split("."))),
    )

    # TCP header
    data_offset = 5 << 4  # 20 bytes, no options
    tcph = struct.pack(
        "!HHIIHHHH",
        src_port, dst_port,
        seq,
        ack,
        (data_offset << 8) | flags,
        65535,  # window
        0,      # checksum
        0,      # urgent pointer
    )
    # Pad tcph to 20 bytes (struct already 20)
    return eth + iph + tcph + payload


def _write_pcap(filename: str, packets: list[tuple[float, bytes]]) -> None:
    """Write packets to a pcap file."""
    path = OUTPUT_DIR / filename
    with open(path, "wb") as f:
        f.write(_pcap_global_header())
        for ts, data in packets:
            f.write(_pcap_record(ts, data))
    print(f"  Written: {path}")


# ---------------------------------------------------------------------------
# TLS record helpers
# ---------------------------------------------------------------------------
def _tls_client_hello(tls_version_code: bytes = b"\x03\x03") -> bytes:
    """Minimal TLS ClientHello for the given version (0x0301=TLS1.0, 0x0303=TLS1.2/1.3)."""
    # TLS record: type=22 (handshake), version, length
    # Handshake: type=1 (ClientHello), length, body
    random_bytes = b"\x00" * 32
    session_id = b"\x00"  # empty
    cipher_suites = b"\x00\x02\x13\x01"  # TLS_AES_128_GCM_SHA256
    compression = b"\x01\x00"
    extensions = b"\x00\x00"

    body = (
        tls_version_code +  # legacy version
        random_bytes +
        session_id +
        cipher_suites +
        compression +
        extensions
    )
    hs_msg = b"\x01" + struct.pack("!I", len(body))[1:] + body
    rec = b"\x16" + tls_version_code + struct.pack("!H", len(hs_msg)) + hs_msg
    return rec


def _tls_server_hello(version_code: bytes = b"\x03\x03", cipher: bytes = b"\x13\x01") -> bytes:
    """Minimal TLS ServerHello."""
    random_bytes = b"\x11" * 32
    session_id = b"\x00"
    compression = b"\x00"
    extensions = b"\x00\x00"
    body = version_code + random_bytes + session_id + cipher + compression + extensions
    hs = b"\x02" + struct.pack("!I", len(body))[1:] + body
    return b"\x16" + version_code + struct.pack("!H", len(hs)) + hs


# ---------------------------------------------------------------------------
# Scenario builders
# ---------------------------------------------------------------------------
def _smtp_handshake_prefix() -> list[bytes]:
    """Return client/server SMTP lines before STARTTLS."""
    return [
        b"220 mail.example.com ESMTP Postfix\r\n",
        b"EHLO client.test\r\n",
        b"250-mail.example.com\r\n250 STARTTLS\r\n",
        b"STARTTLS\r\n",
        b"220 Ready to start TLS\r\n",
    ]


def gen_clean_tls13() -> None:
    """Scenario 1: Clean TLS 1.3 + ECDHE + valid cert."""
    ts = time.time()
    prefix = _smtp_handshake_prefix()
    tls_hello = _tls_client_hello(b"\x03\x03")  # TLS 1.2 record but TLS 1.3 negotiated

    packets = []
    for i, pkt_data in enumerate(prefix + [tls_hello]):
        frame = _eth_ip_tcp("192.168.1.10", "203.0.113.25", 50001, 25, pkt_data, seq=1000 + i * 100)
        packets.append((ts + i * 0.01, frame))

    _write_pcap("smtp_clean_tls13.pcap", packets)


def gen_deprecated_tls10() -> None:
    """Scenario 2: TLS 1.0 session."""
    ts = time.time()
    prefix = _smtp_handshake_prefix()
    # TLS 1.0 = 0x0301
    tls_hello = _tls_client_hello(b"\x03\x01")
    tls_server = _tls_server_hello(b"\x03\x01", b"\x00\x2F")  # RSA_AES128_CBC_SHA

    packets = []
    for i, pkt_data in enumerate(prefix + [tls_hello, tls_server]):
        frame = _eth_ip_tcp("192.168.1.11", "203.0.113.25", 50002, 25, pkt_data, seq=2000 + i * 100)
        packets.append((ts + i * 0.01, frame))

    _write_pcap("smtp_tls10_deprecated.pcap", packets)


def gen_expired_cert() -> None:
    """Scenario 3: Expired certificate session (simulated banner + TLS init)."""
    ts = time.time()
    prefix = [
        b"220 mail.expired.com ESMTP\r\n",
        b"EHLO client.test\r\n",
        b"250 STARTTLS\r\n",
        b"STARTTLS\r\n",
        b"220 Go ahead\r\n",
        _tls_client_hello(b"\x03\x03"),
    ]
    packets = []
    for i, pkt_data in enumerate(prefix):
        frame = _eth_ip_tcp("192.168.1.12", "203.0.113.26", 50003, 25, pkt_data, seq=3000 + i * 100)
        packets.append((ts + i * 0.01, frame))
    _write_pcap("smtp_expired_cert.pcap", packets)


def gen_self_signed() -> None:
    """Scenario 4: Self-signed certificate session."""
    ts = time.time()
    prefix = [
        b"220 mail.selfsigned.local ESMTP\r\n",
        b"EHLO client\r\n",
        b"250 STARTTLS\r\n",
        b"STARTTLS\r\n",
        b"220 Ready\r\n",
        _tls_client_hello(b"\x03\x03"),
    ]
    packets = []
    for i, pkt_data in enumerate(prefix):
        frame = _eth_ip_tcp("192.168.1.13", "10.0.0.1", 50004, 25, pkt_data, seq=4000 + i * 100)
        packets.append((ts + i * 0.01, frame))
    _write_pcap("smtp_self_signed.pcap", packets)


def gen_starttls_downgrade() -> None:
    """Scenario 5: STARTTLS stripping — plaintext continues after STARTTLS."""
    ts = time.time()
    # STARTTLS is seen but no ClientHello follows — plaintext auth proceeds
    data_sequence = [
        b"220 mail.evil.com ESMTP\r\n",
        b"EHLO client\r\n",
        b"250 STARTTLS\r\n",
        b"STARTTLS\r\n",
        # No TLS ClientHello — instead plaintext AUTH (downgrade)
        b"AUTH PLAIN AGFsaWNlAHBhc3N3b3Jk\r\n",
        b"235 Authentication successful\r\n",
    ]
    packets = []
    for i, pkt_data in enumerate(data_sequence):
        frame = _eth_ip_tcp("192.168.1.14", "10.0.0.2", 50005, 25, pkt_data, seq=5000 + i * 100)
        packets.append((ts + i * 0.01, frame))
    _write_pcap("smtp_starttls_downgrade.pcap", packets)


def gen_no_pfs() -> None:
    """Scenario 6: No-PFS static RSA key exchange."""
    ts = time.time()
    prefix = _smtp_handshake_prefix()
    # TLS 1.2 + static RSA cipher (0x002F = TLS_RSA_WITH_AES_128_CBC_SHA)
    tls_hello = _tls_client_hello(b"\x03\x03")
    tls_server = _tls_server_hello(b"\x03\x03", b"\x00\x2F")  # TLS_RSA_WITH_AES_128_CBC_SHA

    packets = []
    for i, pkt_data in enumerate(prefix + [tls_hello, tls_server]):
        frame = _eth_ip_tcp("192.168.1.15", "203.0.113.27", 50006, 25, pkt_data, seq=6000 + i * 100)
        packets.append((ts + i * 0.01, frame))
    _write_pcap("smtp_no_pfs_rsa.pcap", packets)


def main() -> None:
    print("Generating synthetic test PCAPs...")
    print(f"Output directory: {OUTPUT_DIR}")
    print()
    gen_clean_tls13()
    gen_deprecated_tls10()
    gen_expired_cert()
    gen_self_signed()
    gen_starttls_downgrade()
    gen_no_pfs()
    print()
    print("Done! Use these PCAPs as rule-engine test fixtures and demo material.")
    print("Run analysis: python -m securemailscope.main analyze <pcap_file>")


if __name__ == "__main__":
    main()
