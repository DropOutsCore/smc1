"""
securemailscope/tests/conftest.py
------------------------------------
Shared fixtures for pytest test suite.
"""

from __future__ import annotations

import datetime
import os
from pathlib import Path

import pytest

# Path to sample PCAPs shipped with the project
SAMPLE_PCAP_DIR = Path(__file__).parent.parent / "sample_pcaps"


@pytest.fixture
def sample_pcap_dir() -> Path:
    return SAMPLE_PCAP_DIR


@pytest.fixture
def mock_tcp_stream():
    """Return a minimal TCPStream for testing."""
    from securemailscope.ingestion.models import TCPStream, RawSegment

    banner = b"220 mail.example.com ESMTP Postfix\r\n"
    starttls_exchange = (
        b"EHLO client.example.com\r\n"
        b"250-mail.example.com\r\n250 STARTTLS\r\n"
        b"STARTTLS\r\n"
        b"220 Ready to start TLS\r\n"
        # Minimal TLS ClientHello header bytes
        b"\x16\x03\x01\x00\x05"
    )
    data = banner + starttls_exchange

    segs = [
        RawSegment(
            packet_number=1, byte_offset=0, data=data,
            timestamp=1700000000.0,
            src_ip="192.168.1.100", dst_ip="192.168.1.1",
            src_port=45678, dst_port=25,
        )
    ]
    stream = TCPStream(
        stream_key="192.168.1.100:45678-192.168.1.1:25",
        src_ip="192.168.1.100", dst_ip="192.168.1.1",
        src_port=45678, dst_port=25,
        client_data=data, server_data=banner, combined_data=data,
        segments=segs, first_packet=1, last_packet=1,
    )
    return stream


@pytest.fixture
def mock_session(mock_tcp_stream):
    """Return an EmailSession built from mock_tcp_stream."""
    from securemailscope.ingestion.protocol_detector import (
        build_email_sessions, detect_starttls, identify_protocol
    )
    from securemailscope.ingestion.models import EmailSession
    import uuid

    return EmailSession(
        session_id=str(uuid.uuid4()),
        protocol="SMTP",
        src_ip="192.168.1.100", dst_ip="192.168.1.1",
        src_port=45678, dst_port=25,
        stream=mock_tcp_stream,
        starttls_detected=True,
        starttls_offset=len(mock_tcp_stream.combined_data) - 5,
        is_implicit_tls=False,
        banner="220 mail.example.com ESMTP Postfix",
        packet_refs=[1],
    )


@pytest.fixture
def mock_tls_info():
    """Return a TLSHandshakeInfo representing a weak TLS 1.0 + static RSA session."""
    from securemailscope.tls_analysis.handshake_parser import TLSHandshakeInfo
    return TLSHandshakeInfo(
        tls_version="TLS1.0",
        cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA",
        cipher_strength="weak",
        key_exchange="RSA",
        pfs=False,
        sni="mail.example.com",
    )


@pytest.fixture
def mock_cert_info_expired():
    """Return a CertificateInfo representing an expired self-signed cert."""
    from securemailscope.certs.extractor import CertificateInfo
    import datetime
    return CertificateInfo(
        subject="CN=mail.example.com",
        issuer="CN=mail.example.com",
        key_algorithm="RSA",
        key_length=1024,          # weak
        key_strength="weak",
        signature_algorithm="sha1",
        signature_algorithm_weak=True,
        not_after=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc),
        is_expired=True,
        days_until_expiry=-1000,
        is_self_signed=True,
        hostname_match=False,
    )
