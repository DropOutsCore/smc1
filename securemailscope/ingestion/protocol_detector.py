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
_SMTP_BANNER = re.compile(rb"^220[ -]", re.MULTILINE)
_IMAP_BANNER = re.compile(rb"\*\s+OK\b", re.MULTILINE | re.IGNORECASE)
_POP3_BANNER = re.compile(rb"^\+OK\b", re.MULTILINE)

# Additional payload command patterns for non-standard ports or missing banners
_SMTP_CMDS = re.compile(rb"^(?:EHLO|HELO|MAIL FROM:|RCPT TO:)\b", re.MULTILINE | re.IGNORECASE)
_IMAP_CMDS = re.compile(rb"(?:CAPABILITY|LOGIN|AUTHENTICATE|SELECT|EXAMINE)\b", re.IGNORECASE)
_POP3_CMDS = re.compile(rb"^(?:USER|PASS|STAT|LIST|RETR|DELE|STLS)\b", re.MULTILINE | re.IGNORECASE)

# STARTTLS / STLS command patterns:
# Matches SMTP "STARTTLS\r\n", IMAP "tag STARTTLS\r\n", and POP3 "STLS\r\n"
_STARTTLS_CMD = re.compile(rb"(?:STARTTLS|STLS)\r?\n", re.IGNORECASE)
_SMTP_STARTTLS_OK = re.compile(rb"^220[ -].*ready\b", re.MULTILINE | re.IGNORECASE)
_IMAP_STARTTLS_OK = re.compile(rb"\bOK\b.*(?:begin|start).*tls\b", re.MULTILINE | re.IGNORECASE)
_POP3_STARTTLS_OK = re.compile(rb"^\+OK", re.MULTILINE)

# TLS Handshake / ClientHello magic: record type 0x16 (22), version 0x03xx, 2-byte length
_TLS_CLIENT_HELLO = re.compile(rb"\x16\x03[\x00-\x04].{2}", re.DOTALL)
# TLS ServerHello magic: record type 0x16 (22), version 0x03xx, 2-byte length, handshake type 0x02
_TLS_SERVER_RECORD = re.compile(rb"\x16\x03[\x00-\x04].{2}\x02", re.DOTALL)
# Any TLS record start
_TLS_RECORD_ANY = re.compile(rb"[\x14-\x17]\x03[\x00-\x04]", re.DOTALL)


def identify_protocol(stream: TCPStream) -> ProtocolType:
    """
    Determine the base email protocol (SMTP, IMAP, POP3) carried by a TCP stream.

    Checks (in priority order):
    1. Destination port (well-known)
    2. Source port (server may be on standard port, client on ephemeral)
    3. Payload banner bytes
    4. Client / server command patterns
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

    # Command sniffing across payloads
    payload_sample = (stream.client_data or b"")[:4096] + combined_sample[:4096]
    if _SMTP_CMDS.search(payload_sample):
        return ProtocolType.SMTP
    if _IMAP_CMDS.search(payload_sample):
        return ProtocolType.IMAP
    if _POP3_CMDS.search(payload_sample):
        return ProtocolType.POP3

    return ProtocolType.UNKNOWN


def is_stream_implicit_tls(stream: TCPStream) -> bool:
    """
    Determine if the stream runs implicit TLS (e.g. SMTPS/465, IMAPS/993, POP3S/995).

    Prefers observed network traffic over port assumptions when PCAP evidence is available:
    if client sends TLS ClientHello immediately without prior plaintext application banners,
    it is treated as implicit TLS.
    """
    if stream.dst_port in _IMPLICIT_TLS_PORTS or stream.src_port in _IMPLICIT_TLS_PORTS:
        return True

    # Check if stream client traffic starts directly with a TLS ClientHello
    cdata = stream.client_data.lstrip(b"\r\n\x00") if stream.client_data else b""
    if cdata.startswith(b"\x16\x03") and _TLS_CLIENT_HELLO.match(cdata):
        sdata = stream.server_data[:128] if stream.server_data else b""
        if not any(pat.search(sdata) for pat in (_SMTP_BANNER, _IMAP_BANNER, _POP3_BANNER)):
            return True

    return False


def classify_protocol_label(
    base_proto: ProtocolType,
    dst_port: int,
    is_implicit: bool,
    starttls_detected: bool,
    downgrade_suspected: bool = False,
) -> str:
    """
    Map observed protocol, port, and security negotiation to precise standardized labels:
    - Port 465 / implicit SMTP -> 'SMTPS / implicit TLS'
    - Port 587 / SMTP with STARTTLS -> 'SMTP STARTTLS'
    - Plaintext SMTP -> 'SMTP'
    - Port 143 / IMAP with STARTTLS -> 'IMAP STARTTLS'
    - Plaintext IMAP -> 'IMAP'
    - Port 993 / implicit IMAP -> 'IMAPS / implicit TLS'
    - Port 110 with STLS -> 'POP3 STARTTLS'
    - Plaintext POP3 -> 'POP3 / plaintext'
    - Port 995 / implicit POP3 -> 'POP3S / implicit TLS'
    """
    if base_proto == ProtocolType.SMTP:
        if is_implicit or dst_port == 465:
            return ProtocolType.SMTPS.value
        if starttls_detected and not downgrade_suspected:
            return ProtocolType.SMTP_STARTTLS.value
        return ProtocolType.SMTP.value

    if base_proto == ProtocolType.IMAP:
        if is_implicit or dst_port == 993:
            return ProtocolType.IMAPS.value
        if starttls_detected and not downgrade_suspected:
            return ProtocolType.IMAP_STARTTLS.value
        return ProtocolType.IMAP.value

    if base_proto == ProtocolType.POP3:
        if is_implicit or dst_port == 995:
            return ProtocolType.POP3S.value
        if starttls_detected and not downgrade_suspected:
            return ProtocolType.POP3_STARTTLS.value
        return ProtocolType.POP3_PLAINTEXT.value

    return base_proto.value


def detect_starttls(stream: TCPStream) -> StarttlsResult:
    """
    Locate the STARTTLS / STLS command and the resulting TLS ClientHello.

    Returns
    -------
    StarttlsResult
        detected=True if a STARTTLS or STLS command was found.
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

    # Find the packet containing the STARTTLS / STLS command
    result.command_packet = _byte_offset_to_packet(stream, cmd_match.start())

    # Look for TLS ClientHello after the STARTTLS command in combined_data
    tls_match = _TLS_CLIENT_HELLO.search(data, cmd_end)
    if not tls_match and stream.client_data:
        # Check in reassembled client_data
        client_cmd = _STARTTLS_CMD.search(stream.client_data)
        client_cmd_end = client_cmd.end() if client_cmd else 0
        c_match = _TLS_CLIENT_HELLO.search(stream.client_data, client_cmd_end)
        if c_match:
            hello_bytes = stream.client_data[c_match.start():c_match.start() + 16]
            c_offset = data.find(hello_bytes, cmd_end)
            if c_offset != -1:
                tls_match = type("Match", (), {"start": lambda: c_offset})()

    if tls_match:
        result.starttls_offset = tls_match.start()
        result.response_packet = _byte_offset_to_packet(stream, tls_match.start())
    else:
        # STARTTLS / STLS seen, check if plaintext followed (downgrade!)
        trailing = data[cmd_end:]
        # If client sends further plaintext commands (AUTH, USER, PASS, MAIL FROM)
        has_subsequent_plaintext = (
            b"AUTH " in trailing or
            b"USER " in trailing or
            b"PASS " in trailing or
            b"MAIL FROM" in trailing or
            b"a00" in trailing
        )
        if has_subsequent_plaintext or len(trailing.strip()) > 30:
            result.downgrade_suspected = True
            result.downgrade_evidence_packet = result.command_packet
            logger.warning(
                "STARTTLS downgrade suspected on stream %s: command found at byte %d "
                "but no ClientHello followed.",
                stream.stream_key,
                cmd_match.start(),
            )
        return result

    # Additional downgrade check: unencrypted authentication sent after TLS offset
    post_tls = data[result.starttls_offset:]
    if b"AUTH PLAIN" in post_tls[:256] or b"AUTH LOGIN" in post_tls[:256]:
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
    Convert reassembled TCP streams into EmailSession objects with accurate
    protocol classification and normalized session direction.

    Filters out streams that cannot be identified as email protocols.
    """
    sessions: list[EmailSession] = []
    for stream in streams:
        proto = identify_protocol(stream)
        if proto == ProtocolType.UNKNOWN:
            continue

        is_implicit = is_stream_implicit_tls(stream)

        starttls = StarttlsResult()
        if not is_implicit:
            starttls = detect_starttls(stream)

        proto_label = classify_protocol_label(
            base_proto=proto,
            dst_port=stream.dst_port,
            is_implicit=is_implicit,
            starttls_detected=starttls.detected,
            downgrade_suspected=starttls.downgrade_suspected,
        )

        banner = _extract_banner(stream)
        packet_refs = sorted({s.packet_number for s in stream.segments})

        session = EmailSession(
            session_id=str(uuid.uuid4()),
            protocol=proto_label,
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
            proto_label,
            stream.src_ip, stream.src_port,
            stream.dst_ip, stream.dst_port,
            starttls.detected,
            is_implicit,
        )

    logger.info("Built %d email sessions from %d streams", len(sessions), len(streams))
    return sessions
