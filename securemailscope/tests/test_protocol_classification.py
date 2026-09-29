"""
securemailscope/tests/test_protocol_classification.py
------------------------------------------------------
Regression tests for TLS session detection, handshake parsing,
and protocol classification per PRD & user specifications:
  - SMTP STARTTLS (port 587 / 25)
  - IMAP STARTTLS (port 143)
  - SMTPS / implicit TLS (port 465)
  - IMAPS / implicit TLS (port 993)
  - POP3 STARTTLS / STLS (port 110)
  - POP3 plaintext (port 110)
  - POP3S / implicit TLS (port 995)
  - Normalization of session direction: Client IP:Port -> Mail Server IP:Port
  - Full end-to-end validation of the 5-session sample PCAP
"""

from __future__ import annotations

import os
from pathlib import Path
import pytest

from securemailscope.ingestion.models import ProtocolType, RawSegment, TCPStream
from securemailscope.ingestion.protocol_detector import (
    build_email_sessions,
    detect_starttls,
    identify_protocol,
    is_stream_implicit_tls,
)
from securemailscope.ingestion.reassembler import reconstruct_tcp_streams
from securemailscope.pipeline import PipelineConfig, run
from securemailscope.sample_pcaps.generate_test_pcaps import (
    _generate_test_cert_der,
    _tls_certificate_record,
    _tls_client_hello,
    _tls_server_hello,
    _tls_server_hello_done,
    _tls_server_key_exchange,
    gen_multi_protocol_sample,
)
from securemailscope.tls_analysis.handshake_parser import parse_handshake


def test_smtp_starttls_detection_and_classification():
    """Verify SMTP STARTTLS on port 587 is classified and TLS telemetry is populated."""
    cert_der = _generate_test_cert_der("mail.corp25.com")
    c_hello = _tls_client_hello(b"\x03\x03", sni="mail.corp25.com")
    s_hello = (
        _tls_server_hello(b"\x03\x03", cipher=b"\xC0\x30")
        + _tls_certificate_record(cert_der)
        + _tls_server_key_exchange(curve_id=0x0017)
        + _tls_server_hello_done()
    )

    segs = [
        RawSegment(1, 0, b"220 mail.corp25.com ESMTP\r\n", 1.0, "10.0.0.25", "192.168.1.50", 587, 45120),
        RawSegment(2, 0, b"EHLO client.test\r\n", 1.1, "192.168.1.50", "10.0.0.25", 45120, 587),
        RawSegment(3, 27, b"250 STARTTLS\r\n", 1.2, "10.0.0.25", "192.168.1.50", 587, 45120),
        RawSegment(4, 18, b"STARTTLS\r\n", 1.3, "192.168.1.50", "10.0.0.25", 45120, 587),
        RawSegment(5, 41, b"220 Go ahead\r\n", 1.4, "10.0.0.25", "192.168.1.50", 587, 45120),
        RawSegment(6, 28, c_hello, 1.5, "192.168.1.50", "10.0.0.25", 45120, 587),
        RawSegment(7, 55, s_hello, 1.6, "10.0.0.25", "192.168.1.50", 587, 45120),
    ]

    streams = reconstruct_tcp_streams(segs)
    assert len(streams) == 1
    stream = streams[0]

    # Verify direction normalized as Client -> Mail Server
    assert stream.src_ip == "192.168.1.50"
    assert stream.src_port == 45120
    assert stream.dst_ip == "10.0.0.25"
    assert stream.dst_port == 587

    sessions = build_email_sessions(streams)
    assert len(sessions) == 1
    session = sessions[0]

    assert session.protocol == "SMTP STARTTLS"
    assert session.starttls_detected is True
    assert session.downgrade_suspected is False
    assert session.src_ip == "192.168.1.50"
    assert session.dst_ip == "10.0.0.25"

    tls_info = parse_handshake(
        stream.combined_data,
        start_offset=session.starttls_offset or 0,
        handshake_start_packet=1,
        client_data=stream.client_data,
        server_data=stream.server_data,
    )
    assert tls_info.tls_version == "TLS1.2"
    assert tls_info.cipher_suite == "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    assert tls_info.key_exchange == "ECDHE (secp256r1)"
    assert tls_info.pfs is True
    assert tls_info.sni == "mail.corp25.com"
    assert len(tls_info.certificate_chain_der) == 1


def test_imap_starttls_detection_and_classification():
    """Verify IMAP STARTTLS on port 143 is classified as IMAP STARTTLS."""
    cert_der = _generate_test_cert_der("imap.corp14.com")
    c_hello = _tls_client_hello(b"\x03\x03", sni="imap.corp14.com")
    s_hello = (
        _tls_server_hello(b"\x03\x03", cipher=b"\xC0\x2F")
        + _tls_certificate_record(cert_der)
        + _tls_server_key_exchange(curve_id=0x0017)
        + _tls_server_hello_done()
    )

    segs = [
        RawSegment(1, 0, b"* OK [CAPABILITY IMAP4rev1 STARTTLS] Dovecot ready.\r\n", 2.0, "10.0.0.14", "192.168.1.51", 143, 45122),
        RawSegment(2, 0, b"a001 STARTTLS\r\n", 2.1, "192.168.1.51", "10.0.0.14", 45122, 143),
        RawSegment(3, 53, b"a001 OK Begin TLS negotiation now.\r\n", 2.2, "10.0.0.14", "192.168.1.51", 143, 45122),
        RawSegment(4, 15, c_hello, 2.3, "192.168.1.51", "10.0.0.14", 45122, 143),
        RawSegment(5, 88, s_hello, 2.4, "10.0.0.14", "192.168.1.51", 143, 45122),
    ]

    streams = reconstruct_tcp_streams(segs)
    assert len(streams) == 1
    stream = streams[0]
    sessions = build_email_sessions(streams)
    assert len(sessions) == 1
    session = sessions[0]

    assert session.protocol == "IMAP STARTTLS"
    assert session.starttls_detected is True
    assert session.src_ip == "192.168.1.51"
    assert session.dst_ip == "10.0.0.14"
    assert session.dst_port == 143

    tls_info = parse_handshake(
        stream.combined_data,
        start_offset=session.starttls_offset or 0,
        handshake_start_packet=1,
        client_data=stream.client_data,
        server_data=stream.server_data,
    )
    assert tls_info.tls_version == "TLS1.2"
    assert tls_info.cipher_suite == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    assert tls_info.key_exchange == "ECDHE (secp256r1)"
    assert tls_info.pfs is True
    assert tls_info.sni == "imap.corp14.com"


def test_smtps_465_implicit_tls_classification():
    """Verify Port 465 is classified as 'SMTPS / implicit TLS', NOT SMTP."""
    c_hello = _tls_client_hello(b"\x03\x03", sni="smtps.corp46.com")
    s_hello = _tls_server_hello(b"\x03\x03", cipher=b"\x13\x02", is_tls13=True, key_share_group=0x001D)

    segs = [
        RawSegment(1, 0, c_hello, 3.0, "192.168.1.52", "10.0.0.46", 45124, 465),
        RawSegment(2, 0, s_hello, 3.1, "10.0.0.46", "192.168.1.52", 465, 45124),
    ]

    streams = reconstruct_tcp_streams(segs)
    sessions = build_email_sessions(streams)
    assert len(sessions) == 1
    session = sessions[0]

    assert session.protocol == "SMTPS / implicit TLS"
    assert session.protocol != "SMTP"
    assert session.is_implicit_tls is True
    assert session.src_ip == "192.168.1.52"
    assert session.dst_ip == "10.0.0.46"
    assert session.dst_port == 465


def test_imaps_993_and_pop3s_995_implicit_tls():
    """Verify ports 993 and 995 are classified as IMAPS and POP3S implicit TLS."""
    # IMAPS / 993
    s_imaps = [
        RawSegment(1, 0, b"\x16\x03\x03\x00\x05", 4.0, "192.168.1.60", "10.0.0.99", 50000, 993),
    ]
    sess_imaps = build_email_sessions(reconstruct_tcp_streams(s_imaps))
    assert len(sess_imaps) == 1
    assert sess_imaps[0].protocol == "IMAPS / implicit TLS"
    assert sess_imaps[0].is_implicit_tls is True

    # POP3S / 995
    s_pop3s = [
        RawSegment(1, 0, b"\x16\x03\x03\x00\x05", 4.1, "192.168.1.61", "10.0.0.98", 50001, 995),
    ]
    sess_pop3s = build_email_sessions(reconstruct_tcp_streams(s_pop3s))
    assert len(sess_pop3s) == 1
    assert sess_pop3s[0].protocol == "POP3S / implicit TLS"
    assert sess_pop3s[0].is_implicit_tls is True


def test_pop3_stls_detection_and_classification():
    """Verify POP3 port 110 with STLS command is classified as POP3 STARTTLS."""
    c_hello = _tls_client_hello(b"\x03\x03", sni="pop3.corp13.com")
    s_hello = _tls_server_hello(b"\x03\x03", cipher=b"\xC0\x2F")

    segs = [
        RawSegment(1, 0, b"+OK POP3 server ready\r\n", 5.0, "10.0.0.13", "192.168.1.53", 110, 45126),
        RawSegment(2, 0, b"STLS\r\n", 5.1, "192.168.1.53", "10.0.0.13", 45126, 110),
        RawSegment(3, 23, b"+OK Begin TLS\r\n", 5.2, "10.0.0.13", "192.168.1.53", 110, 45126),
        RawSegment(4, 6, c_hello, 5.3, "192.168.1.53", "10.0.0.13", 45126, 110),
        RawSegment(5, 38, s_hello, 5.4, "10.0.0.13", "192.168.1.53", 110, 45126),
    ]

    streams = reconstruct_tcp_streams(segs)
    sessions = build_email_sessions(streams)
    assert len(sessions) == 1
    session = sessions[0]

    assert session.protocol == "POP3 STARTTLS"
    assert session.starttls_detected is True
    assert session.downgrade_suspected is False


def test_pop3_plaintext_classification():
    """Verify POP3 port 110 without STLS is classified as 'POP3 / plaintext'."""
    segs = [
        RawSegment(1, 0, b"+OK POP3 server ready\r\n", 6.0, "10.0.0.13", "192.168.1.53", 110, 45126),
        RawSegment(2, 0, b"USER alice\r\n", 6.1, "192.168.1.53", "10.0.0.13", 45126, 110),
        RawSegment(3, 23, b"+OK send password\r\n", 6.2, "10.0.0.13", "192.168.1.53", 110, 45126),
        RawSegment(4, 12, b"PASS secret\r\n", 6.3, "192.168.1.53", "10.0.0.13", 45126, 110),
        RawSegment(5, 42, b"+OK Mailbox open\r\n", 6.4, "10.0.0.13", "192.168.1.53", 110, 45126),
    ]

    streams = reconstruct_tcp_streams(segs)
    sessions = build_email_sessions(streams)
    assert len(sessions) == 1
    session = sessions[0]

    assert session.protocol == "POP3 / plaintext"
    assert session.starttls_detected is False
    assert session.is_implicit_tls is False


def test_session_direction_normalization():
    """Verify sessions are consistently normalized as Client IP:Port -> Mail Server IP:Port."""
    # Server sends initial greeting as first packet in capture
    segs = [
        RawSegment(1, 0, b"220 mail.server.com ESMTP\r\n", 1.0, "10.0.0.5", "192.168.1.100", 25, 54321),
        RawSegment(2, 0, b"EHLO client\r\n", 1.1, "192.168.1.100", "10.0.0.5", 54321, 25),
    ]

    streams = reconstruct_tcp_streams(segs)
    assert len(streams) == 1
    stream = streams[0]

    # Even though packet 1 came from 10.0.0.5:25, client is recognized as 192.168.1.100:54321
    assert stream.src_ip == "192.168.1.100"
    assert stream.src_port == 54321
    assert stream.dst_ip == "10.0.0.5"
    assert stream.dst_port == 25

    # Original segments still preserve raw packet direction for forensic chain-of-custody
    assert segs[0].src_ip == "10.0.0.5"
    assert segs[1].src_ip == "192.168.1.100"


def test_sample_pcap_end_to_end_validation():
    """
    Validate end-to-end against the multi-protocol sample PCAP matching requirement 4:
      - 192.168.1.50:45120 -> 10.0.0.25:587 (SMTP STARTTLS)
      - 192.168.1.51:45122 -> 10.0.0.14:143 (IMAP STARTTLS)
      - 192.168.1.52:45124 -> 10.0.0.46:465 (SMTPS / implicit TLS)
      - 192.168.1.53:45126 -> 10.0.0.13:110 (POP3 / plaintext)
      - 192.168.1.54:45128 -> 10.0.0.25:587 (SMTP STARTTLS)
    """
    pcap_path = gen_multi_protocol_sample()
    assert os.path.isfile(pcap_path)

    result = run(pcap_path, PipelineConfig(generate_html=False, generate_pdf=False))
    assert result.error is None
    report = result.report

    all_sessions = [
        s for h in report.get("hosts", [])
        for s in h.get("sessions", [])
    ]
    assert len(all_sessions) == 5

    # Build mapping by (src_ip:src_port -> dst_ip:dst_port)
    session_map = {
        f"{s['src_ip']}:{s['src_port']} -> {s['dst_ip']}:{s['dst_port']}": s
        for s in all_sessions
    }

    # 1. 192.168.1.50:45120 -> 10.0.0.25:587 (SMTP STARTTLS)
    k1 = "192.168.1.50:45120 -> 10.0.0.25:587"
    assert k1 in session_map
    s1 = session_map[k1]
    assert s1["protocol"] == "SMTP STARTTLS"
    assert s1["tls_version"] == "TLS1.2"
    assert s1["cipher_suite"] == "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    assert s1["key_exchange"] == "ECDHE (secp256r1)"
    assert s1["pfs"] is True
    assert s1["sni"] == "mail.corp25.com"
    assert s1["certificate"] is not None
    assert "mail.corp25.com" in s1["certificate"]["subject"]

    # 2. 192.168.1.51:45122 -> 10.0.0.14:143 (IMAP STARTTLS)
    k2 = "192.168.1.51:45122 -> 10.0.0.14:143"
    assert k2 in session_map
    s2 = session_map[k2]
    assert s2["protocol"] == "IMAP STARTTLS"
    assert s2["tls_version"] == "TLS1.2"
    assert s2["cipher_suite"] == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    assert s2["key_exchange"] == "ECDHE (secp256r1)"
    assert s2["pfs"] is True
    assert s2["sni"] == "imap.corp14.com"

    # 3. 192.168.1.52:45124 -> 10.0.0.46:465 (SMTPS / implicit TLS)
    k3 = "192.168.1.52:45124 -> 10.0.0.46:465"
    assert k3 in session_map
    s3 = session_map[k3]
    assert s3["protocol"] == "SMTPS / implicit TLS"
    assert s3["tls_version"] == "TLS1.3"
    assert s3["cipher_suite"] == "TLS_AES_256_GCM_SHA384"
    assert s3["key_exchange"] == "ECDHE (x25519)"
    assert s3["pfs"] is True
    assert s3["sni"] == "smtps.corp46.com"
    assert s3["tls13_visibility_limited"] is True
    assert any("TLS 1.3" in note for note in s3.get("not_observable", []))

    # 4. 192.168.1.53:45126 -> 10.0.0.13:110 (POP3 / plaintext)
    k4 = "192.168.1.53:45126 -> 10.0.0.13:110"
    assert k4 in session_map
    s4 = session_map[k4]
    assert s4["protocol"] == "POP3 / plaintext"
    assert s4["tls_version"] == "none"
    assert s4["cipher_suite"] == "none"
    assert s4["pfs"] is False

    # 5. 192.168.1.54:45128 -> 10.0.0.25:587 (SMTP STARTTLS)
    k5 = "192.168.1.54:45128 -> 10.0.0.25:587"
    assert k5 in session_map
    s5 = session_map[k5]
    assert s5["protocol"] == "SMTP STARTTLS"
    assert s5["tls_version"] == "TLS1.2"
    assert s5["cipher_suite"] == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    assert s5["key_exchange"] == "ECDHE (secp256r1)"
    assert s5["pfs"] is True
    assert s5["sni"] == "mail.corp25.com"
