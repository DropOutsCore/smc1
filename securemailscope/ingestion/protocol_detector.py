"""
securemailscope/ingestion/protocol_detector.py
------------------------------------------------
Protocol identification and STARTTLS detection.

Strategy
--------
1. Check well-known ports (25, 587, 465, 143, 993, 110, 995).
2. Check payload banners regardless of port (non-standard deployment support).
3. For STARTTLS: scan plaintext payload for the STARTTLS command/response
   and locate the TLS ClientHello that follows.

FORENSIC NOTE: All decisions reference packet_number so every finding can
be traced back to the original PCAP.
"""

from __future__ import annotations

import logging
import re
import uuid

from securemailscope.ingestion.models import (
    EmailSession,
    ProtocolType,
    StarttlsResult,
    TCPStream,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Well-known port mapping
# ---------------------------------------------------------------------------
_PORT_PROTOCOL: dict[int, ProtocolType] = {
    25:  ProtocolType.SMTP,
    587: ProtocolType.SMTP,
    465: ProtocolType.SMTP,   # SMTPS — implicit TLS
    143: ProtocolType.IMAP,
    993: ProtocolType.IMAP,   # IMAPS — implicit TLS
    110: ProtocolType.POP3,
    995: ProtocolType.POP3,   # POP3S — implicit TLS
}

_IMPLICIT_TLS_PORTS: set[int] = {465, 993, 995}

# Banner patterns (bytes, case-insensitive)
_SMTP_BANNER = re.compile(rb"^220\s", re.MULTILINE)
_IMAP_BANNER = re.compile(rb"\*\s+OK\b", re.MULTILINE | re.IGNORECASE)
_POP3_BANNER = re.compile(rb"^\+OK\b", re.MULTILINE)

# STARTTLS command and success response patterns
_STARTTLS_CMD = re.compile(rb"STARTTLS\r?\n", re.IGNORECASE)
_SMTP_STARTTLS_OK = re.compile(rb"^220\s+.*ready\b", re.MULTILINE | re.IGNORECASE)
_IMAP_STARTTLS_OK = re.compile(rb"\bOK\b.*begin\b.*tls\b", re.MULTILINE | re.IGNORECASE)
_POP3_STARTTLS_OK = re.compile(rb"^\+OK", re.MULTILINE)

# TLS ClientHello magic: record type 0x16, version 0x03xx, handshake type 0x01
_TLS_CLIENT_HELLO = re.compile(rb"\x16\x03[\x00-\x04]\x00.", re.DOTALL)


def identify_protocol(stream: TCPStream) -> ProtocolType:
    """
    Determine the email protocol carried by a TCP stream.

    Checks (in priority order):
    1. Destination port (well-known)
    2. Source port (server may be on standard port, client on ephemeral)
    3. Payload banner bytes
    """
    # Port-based detection (most reliable)
    for port in (stream.dst_port, stream.src_port):
        if port in _PORT_PROTOCOL:
            return _PORT_PROTOCOL[port]

    # Banner-based detection (non-standard ports)
    sample = stream.server_data[:4096] if stream.server_data else b""
    if _SMTP_BANNER.search(sample):
        return ProtocolType.SMTP
    if _IMAP_BANNER.search(sample):
        return ProtocolType.IMAP
    if _POP3_BANNER.search(sample):
        return ProtocolType.POP3

    # Try combined data
    combined_sample = stream.combined_data[:4096]
    if _SMTP_BANNER.search(combined_sample):
        return ProtocolType.SMTP
    if _IMAP_BANNER.search(combined_sample):
        return ProtocolType.IMAP
    if _POP3_BANNER.search(combined_sample):
        return ProtocolType.POP3

    return ProtocolType.UNKNOWN


def detect_starttls(stream: TCPStream) -> StarttlsResult:
    """
    Locate the STARTTLS command and the resulting TLS ClientHello.

    Returns
    -------
    StarttlsResult
        detected=True if a STARTTLS command was found.
        starttls_offset is the byte offset in combined_data where the
        TLS record layer begins (i.e., where encryption starts).
        downgrade_suspected=True if plaintext continued after the command.
    """
    result = StarttlsResult()
    data = stream.combined_data

    cmd_match = _STARTTLS_CMD.search(data)
    if not cmd_match:
        return result

    result.detected = True
    cmd_end = cmd_match.end()

    # Find the packet containing the STARTTLS command
    result.command_packet = _byte_offset_to_packet(stream, cmd_match.start())

    # Look for TLS ClientHello after the STARTTLS command
    tls_match = _TLS_CLIENT_HELLO.search(data, cmd_end)
    if tls_match:
        result.starttls_offset = tls_match.start()
        result.response_packet = _byte_offset_to_packet(stream, tls_match.start())
    else:
        # STARTTLS command seen but no ClientHello followed — downgrade!
        result.downgrade_suspected = True
        result.downgrade_evidence_packet = result.command_packet
        logger.warning(
            "STARTTLS downgrade suspected on stream %s: command found at byte %d "
            "but no ClientHello followed.",
            stream.stream_key,
            cmd_match.start(),
        )
        return result

    # Additional downgrade check: plaintext after STARTTLS offset
    post_tls = data[result.starttls_offset:]
    if _STARTTLS_CMD.search(post_tls) or b"AUTH " in post_tls[:256]:
        result.downgrade_suspected = True
        result.downgrade_evidence_packet = _byte_offset_to_packet(
            stream, result.starttls_offset
        )

    return result


def _byte_offset_to_packet(stream: TCPStream, offset: int) -> int:
    """
    Map a byte offset in combined_data back to the closest packet number.
    Returns the packet number of the segment that covers that offset,
    or the first/last packet number as a fallback.
    """
    accumulated = 0
    sorted_segs = sorted(stream.segments, key=lambda s: (s.timestamp, s.packet_number))
    for seg in sorted_segs:
        accumulated += len(seg.data)
        if accumulated > offset:
            return seg.packet_number
    return stream.last_packet if stream.last_packet else 0


def _extract_banner(stream: TCPStream) -> str:
    """Extract the server greeting banner (first line of server response)."""
    sample = (stream.server_data or b"")[:512]
    try:
        text = sample.decode("ascii", errors="ignore")
        lines = text.splitlines()
        for line in lines:
            stripped = line.strip()
            if stripped:
                return stripped[:256]
    except Exception:
        pass
    return ""


def build_email_sessions(streams: list[TCPStream]) -> list[EmailSession]:
    """
    Convert reassembled TCP streams into EmailSession objects.

    Filters out streams that cannot be identified as email protocols.
    """
    sessions: list[EmailSession] = []
    for stream in streams:
        proto = identify_protocol(stream)
        if proto == ProtocolType.UNKNOWN:
            continue

        is_implicit = (stream.dst_port in _IMPLICIT_TLS_PORTS or
                       stream.src_port in _IMPLICIT_TLS_PORTS)

        starttls = StarttlsResult()
        if not is_implicit:
            starttls = detect_starttls(stream)

        banner = _extract_banner(stream)
        packet_refs = sorted({s.packet_number for s in stream.segments})

        session = EmailSession(
            session_id=str(uuid.uuid4()),
            protocol=proto.value,
            src_ip=stream.src_ip,
            dst_ip=stream.dst_ip,
            src_port=stream.src_port,
            dst_port=stream.dst_port,
            stream=stream,
            starttls_detected=starttls.detected,
            starttls_offset=starttls.starttls_offset,
            downgrade_suspected=starttls.downgrade_suspected,
            downgrade_evidence_packet=starttls.downgrade_evidence_packet,
            is_implicit_tls=is_implicit,
            banner=banner,
            packet_refs=packet_refs,
        )
        sessions.append(session)
        logger.debug(
            "Session %s: %s %s:%d -> %s:%d  STARTTLS=%s  implicit_TLS=%s",
            session.session_id[:8],
            proto.value,
            stream.src_ip, stream.src_port,
            stream.dst_ip, stream.dst_port,
            starttls.detected,
            is_implicit,
        )

    logger.info("Built %d email sessions from %d streams", len(sessions), len(streams))
    return sessions
