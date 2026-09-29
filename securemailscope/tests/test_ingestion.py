"""
Tests for ingestion module.
"""

from __future__ import annotations

import pytest
from securemailscope.ingestion.models import ProtocolType
from securemailscope.ingestion.protocol_detector import (
    identify_protocol, detect_starttls, build_email_sessions
)
from securemailscope.ingestion.reassembler import reconstruct_tcp_streams


def test_protocol_identification_by_port(mock_tcp_stream):
    """Protocol is correctly identified by well-known destination port."""
    proto = identify_protocol(mock_tcp_stream)
    assert proto == ProtocolType.SMTP


def test_protocol_identification_imap():
    """IMAP banner detection on non-standard port."""
    from securemailscope.ingestion.models import TCPStream, RawSegment
    banner = b"* OK Dovecot ready\r\n"
    segs = [RawSegment(1, 0, banner, 1700000000.0, "1.2.3.4", "5.6.7.8", 60000, 12345)]
    stream = TCPStream(
        "1.2.3.4:60000-5.6.7.8:12345", "1.2.3.4", "5.6.7.8", 60000, 12345,
        client_data=b"", server_data=banner, combined_data=banner,
        segments=segs, first_packet=1, last_packet=1,
    )
    proto = identify_protocol(stream)
    assert proto == ProtocolType.IMAP


def test_starttls_detection(mock_tcp_stream):
    """STARTTLS command and TLS ClientHello are detected."""
    result = detect_starttls(mock_tcp_stream)
    assert result.detected is True
    assert result.command_packet is not None
    assert result.downgrade_suspected is False


def test_starttls_downgrade_detection():
    """STARTTLS downgrade is flagged when no ClientHello follows the command."""
    from securemailscope.ingestion.models import TCPStream, RawSegment
    data = (
        b"220 mail.test ESMTP\r\n"
        b"EHLO client\r\n"
        b"250 STARTTLS\r\n"
        b"STARTTLS\r\n"
        b"AUTH PLAIN ...\r\n"   # Plaintext continues — no TLS ClientHello
    )
    segs = [RawSegment(1, 0, data, 1700000000.0, "1.2.3.4", "5.6.7.8", 12345, 25)]
    stream = TCPStream(
        "1.2.3.4:12345-5.6.7.8:25", "1.2.3.4", "5.6.7.8", 12345, 25,
        client_data=data, server_data=b"", combined_data=data,
        segments=segs, first_packet=1, last_packet=1,
    )
    result = detect_starttls(stream)
    assert result.detected is True
    assert result.downgrade_suspected is True


def test_build_sessions_filters_unknown_protocol():
    """Streams with unknown protocol are filtered out."""
    from securemailscope.ingestion.models import TCPStream, RawSegment
    garbage = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    segs = [RawSegment(1, 0, garbage, 1700000000.0, "1.2.3.4", "5.6.7.8", 12345, 80)]
    stream = TCPStream(
        "1.2.3.4:12345-5.6.7.8:80", "1.2.3.4", "5.6.7.8", 12345, 80,
        client_data=garbage, server_data=b"", combined_data=garbage,
        segments=segs, first_packet=1, last_packet=1,
    )
    sessions = build_email_sessions([stream])
    assert sessions == []


def test_implicit_tls_ports():
    """Ports 465/993/995 are correctly flagged as implicit TLS."""
    from securemailscope.ingestion.models import TCPStream, RawSegment
    # IMAPS on 993
    segs = [RawSegment(1, 0, b"\x16\x03\x01", 1700000000.0, "1.2.3.4", "5.6.7.8", 12345, 993)]
    stream = TCPStream(
        "1.2.3.4:12345-5.6.7.8:993", "1.2.3.4", "5.6.7.8", 12345, 993,
        client_data=b"\x16\x03\x01", server_data=b"", combined_data=b"\x16\x03\x01",
        segments=segs, first_packet=1, last_packet=1,
    )
    sessions = build_email_sessions([stream])
    assert len(sessions) == 1
    assert sessions[0].is_implicit_tls is True
    assert sessions[0].protocol == "IMAPS / implicit TLS"


def test_tcp_reassembly_deduplicates_retransmits():
    """Retransmitted segments are deduplicated in reassembly."""
    from securemailscope.ingestion.models import RawSegment
    payload = b"HELO client\r\n"
    # Same payload sent twice (retransmit)
    segs = [
        RawSegment(1, 0, payload, 1700000000.0, "1.2.3.4", "5.6.7.8", 12345, 25),
        RawSegment(2, 0, payload, 1700000001.0, "1.2.3.4", "5.6.7.8", 12345, 25),  # retransmit
    ]
    streams = reconstruct_tcp_streams(segs)
    assert len(streams) == 1
    # Should not duplicate the payload
    assert streams[0].client_data.count(b"HELO client") == 1
