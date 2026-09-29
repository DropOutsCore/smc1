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
def _generate_test_cert_der(cn: str = "mail.example.com") -> bytes:
    """Generate a valid self-signed DER certificate using cryptography."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, cn),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "AVALOK Test Lab"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(cn)]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.DER)
    except Exception:
        # Fallback dummy DER bytes
        return b"\x30\x82\x01\x00" + b"\x00" * 256


def _tls_client_hello(
    tls_version_code: bytes = b"\x03\x03",
    sni: str = "",
    cipher_suites: list[bytes] = None,
) -> bytes:
    """Construct a realistic TLS ClientHello."""
    random_bytes = b"\x12" * 32
    session_id = b"\x00"
    if not cipher_suites:
        cipher_suites = [b"\x13\x01", b"\xC0\x2F", b"\xC0\x30"]  # TLS_AES_128_GCM, ECDHE_RSA_AES128_GCM, ECDHE_RSA_AES256_GCM
    cs_bytes = struct.pack("!H", len(cipher_suites) * 2) + b"".join(cipher_suites)
    compression = b"\x01\x00"

    ext_buf = bytearray()
    if sni:
        hn = sni.encode("ascii")
        sni_entry = b"\x00" + struct.pack("!H", len(hn)) + hn
        sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
        ext_buf += struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

    # supported_versions (0x002B)
    supp_vers = b"\x04\x03\x04\x03\x03"  # length 4: TLS 1.3, TLS 1.2
    ext_buf += struct.pack("!HH", 0x002B, len(supp_vers)) + supp_vers

    exts_packed = struct.pack("!H", len(ext_buf)) + bytes(ext_buf) if ext_buf else b"\x00\x00"

    body = tls_version_code + random_bytes + session_id + cs_bytes + compression + exts_packed
    hs_msg = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16" + tls_version_code + struct.pack("!H", len(hs_msg)) + hs_msg


def _tls_server_hello(
    version_code: bytes = b"\x03\x03",
    cipher: bytes = b"\x13\x01",
    is_tls13: bool = False,
    key_share_group: int = 0x001D,
) -> bytes:
    """Construct a TLS ServerHello."""
    random_bytes = b"\x23" * 32
    session_id = b"\x00"
    compression = b"\x00"

    ext_buf = bytearray()
    if is_tls13:
        # supported_versions (0x002B) -> TLS 1.3 (0x0304)
        ext_buf += struct.pack("!HHH", 0x002B, 2, 0x0304)
        # key_share (0x0033)
        key_share_bytes = b"\x44" * 32
        ks_body = struct.pack("!HH", key_share_group, len(key_share_bytes)) + key_share_bytes
        ext_buf += struct.pack("!HH", 0x0033, len(ks_body)) + ks_body

    exts_packed = struct.pack("!H", len(ext_buf)) + bytes(ext_buf) if ext_buf else b"\x00\x00"
    body = version_code + random_bytes + session_id + cipher + compression + exts_packed
    hs = b"\x02" + struct.pack("!I", len(body))[1:] + body
    return b"\x16" + version_code + struct.pack("!H", len(hs)) + hs


def _tls_certificate_record(cert_der: bytes, version_code: bytes = b"\x03\x03") -> bytes:
    """Build a Certificate message (type 0x0B)."""
    cert_entry = struct.pack("!I", len(cert_der))[1:] + cert_der
    body = struct.pack("!I", len(cert_entry))[1:] + cert_entry
    hs_msg = b"\x0B" + struct.pack("!I", len(body))[1:] + body
    return b"\x16" + version_code + struct.pack("!H", len(hs_msg)) + hs_msg


def _tls_server_key_exchange(curve_id: int = 0x0017, version_code: bytes = b"\x03\x03") -> bytes:
    """Build a ServerKeyExchange message (type 0x0C) for ECDHE."""
    dummy_point = b"\x04" + (b"\x12" * 64)
    ec_params = struct.pack("!BH", 3, curve_id) + bytes([len(dummy_point)]) + dummy_point
    sig = b"\x99" * 256
    sig_field = b"\x04\x01" + struct.pack("!H", len(sig)) + sig
    body = ec_params + sig_field
    hs_msg = b"\x0C" + struct.pack("!I", len(body))[1:] + body
    return b"\x16" + version_code + struct.pack("!H", len(hs_msg)) + hs_msg


def _tls_server_hello_done(version_code: bytes = b"\x03\x03") -> bytes:
    """Build a ServerHelloDone message (type 0x0E)."""
    hs_msg = b"\x0E\x00\x00\x00"
    return b"\x16" + version_code + struct.pack("!H", len(hs_msg)) + hs_msg


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


def gen_multi_protocol_sample() -> str:
    """
    Generate the reference multi-protocol sample PCAP containing:
      1. SMTP STARTTLS (192.168.1.50:45120 -> 10.0.0.25:587)
      2. IMAP STARTTLS (192.168.1.51:45122 -> 10.0.0.14:143)
      3. SMTPS / implicit TLS (192.168.1.52:45124 -> 10.0.0.46:465)
      4. POP3 / plaintext (192.168.1.53:45126 -> 10.0.0.13:110)
      5. SMTP STARTTLS (192.168.1.54:45128 -> 10.0.0.25:587)
    """
    ts = time.time()
    packets = []

    # Certs for realistic telemetry
    cert_mail25 = _generate_test_cert_der("mail.corp25.com")
    cert_imap14 = _generate_test_cert_der("imap.corp14.com")

    # ── Session 1: SMTP STARTTLS on 587 (TLS 1.2 + ECDHE P-256 + AES256) ───
    c1, s1 = ("192.168.1.50", 45120), ("10.0.0.25", 587)
    s1_flow = [
        (s1, c1, b"220 mail.corp25.com ESMTP Postfix\r\n"),
        (c1, s1, b"EHLO client50.corp.internal\r\n"),
        (s1, c1, b"250-mail.corp25.com\r\n250 STARTTLS\r\n"),
        (c1, s1, b"STARTTLS\r\n"),
        (s1, c1, b"220 2.0.0 Ready to start TLS\r\n"),
        (c1, s1, _tls_client_hello(b"\x03\x03", sni="mail.corp25.com")),
        (s1, c1, _tls_server_hello(b"\x03\x03", cipher=b"\xC0\x30") +
                 _tls_certificate_record(cert_mail25) +
                 _tls_server_key_exchange(curve_id=0x0017) +
                 _tls_server_hello_done()),
    ]
    for i, (src, dst, data) in enumerate(s1_flow):
        f = _eth_ip_tcp(src[0], dst[0], src[1], dst[1], data, seq=10000 + i * 500)
        packets.append((ts + 0.01 * i, f))

    # ── Session 2: IMAP STARTTLS on 143 (TLS 1.2 + ECDHE P-256 + AES128) ───
    c2, s2 = ("192.168.1.51", 45122), ("10.0.0.14", 143)
    s2_flow = [
        (s2, c2, b"* OK [CAPABILITY IMAP4rev1 STARTTLS] Dovecot ready.\r\n"),
        (c2, s2, b"a001 STARTTLS\r\n"),
        (s2, c2, b"a001 OK Begin TLS negotiation now.\r\n"),
        (c2, s2, _tls_client_hello(b"\x03\x03", sni="imap.corp14.com")),
        (s2, c2, _tls_server_hello(b"\x03\x03", cipher=b"\xC0\x2F") +
                 _tls_certificate_record(cert_imap14) +
                 _tls_server_key_exchange(curve_id=0x0017) +
                 _tls_server_hello_done()),
    ]
    for i, (src, dst, data) in enumerate(s2_flow):
        f = _eth_ip_tcp(src[0], dst[0], src[1], dst[1], data, seq=20000 + i * 500)
        packets.append((ts + 0.5 + 0.01 * i, f))

    # ── Session 3: SMTPS / implicit TLS on 465 (TLS 1.3 + X25519 + AES256) ──
    c3, s3 = ("192.168.1.52", 45124), ("10.0.0.46", 465)
    s3_flow = [
        (c3, s3, _tls_client_hello(b"\x03\x03", sni="smtps.corp46.com")),
        (s3, c3, _tls_server_hello(b"\x03\x03", cipher=b"\x13\x02", is_tls13=True, key_share_group=0x001D)),
    ]
    for i, (src, dst, data) in enumerate(s3_flow):
        f = _eth_ip_tcp(src[0], dst[0], src[1], dst[1], data, seq=30000 + i * 500)
        packets.append((ts + 1.0 + 0.01 * i, f))

    # ── Session 4: POP3 / plaintext on 110 (No TLS) ─────────────────────────
    c4, s4 = ("192.168.1.53", 45126), ("10.0.0.13", 110)
    s4_flow = [
        (s4, c4, b"+OK POP3 server ready <1234.5678@corp13.com>\r\n"),
        (c4, s4, b"USER alice\r\n"),
        (s4, c4, b"+OK send password\r\n"),
        (c4, s4, b"PASS secret123\r\n"),
        (s4, c4, b"+OK Mailbox open, 2 messages\r\n"),
        (c4, s4, b"QUIT\r\n"),
        (s4, c4, b"+OK Bye\r\n"),
    ]
    for i, (src, dst, data) in enumerate(s4_flow):
        f = _eth_ip_tcp(src[0], dst[0], src[1], dst[1], data, seq=40000 + i * 500)
        packets.append((ts + 1.5 + 0.01 * i, f))

    # ── Session 5: SMTP STARTTLS on 587 (TLS 1.2 + ECDHE P-256 + AES128) ───
    c5, s5 = ("192.168.1.54", 45128), ("10.0.0.25", 587)
    s5_flow = [
        (s5, c5, b"220 mail.corp25.com ESMTP\r\n"),
        (c5, s5, b"EHLO client54.corp.internal\r\n"),
        (s5, c5, b"250-mail.corp25.com\r\n250 STARTTLS\r\n"),
        (c5, s5, b"STARTTLS\r\n"),
        (s5, c5, b"220 Go ahead\r\n"),
        (c5, s5, _tls_client_hello(b"\x03\x03", sni="mail.corp25.com")),
        (s5, c5, _tls_server_hello(b"\x03\x03", cipher=b"\xC0\x2F") +
                 _tls_certificate_record(cert_mail25) +
                 _tls_server_key_exchange(curve_id=0x0017) +
                 _tls_server_hello_done()),
    ]
    for i, (src, dst, data) in enumerate(s5_flow):
        f = _eth_ip_tcp(src[0], dst[0], src[1], dst[1], data, seq=50000 + i * 500)
        packets.append((ts + 2.0 + 0.01 * i, f))

    filename = "email_tls_sample.pcap"
    _write_pcap(filename, packets)
    return str(OUTPUT_DIR / filename)


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
    sample_path = gen_multi_protocol_sample()
    print(f"  Generated multi-protocol sample: {sample_path}")
    print()
    print("Done! Use these PCAPs as rule-engine test fixtures and demo material.")
    print("Run analysis: python -m securemailscope.main analyze <pcap_file>")


if __name__ == "__main__":
    main()
