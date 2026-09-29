"""
securemailscope/ingestion/reassembler.py
------------------------------------------
TCP stream reassembly from raw segments.

Handles:
  - Out-of-order segments (sorted by sequence number)
  - Retransmissions (deduplicated by seq+data overlap)
  - Bidirectional flow separation (client→server vs server→client)
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import NamedTuple

from securemailscope.ingestion.models import RawSegment, TCPStream

logger = logging.getLogger(__name__)


class _FlowKey(NamedTuple):
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int


def reconstruct_tcp_streams(segments: list[RawSegment]) -> list[TCPStream]:
    """
    Reassemble all TCP streams from a flat list of segments.

    Algorithm
    ---------
    1. Group segments into bidirectional flows (canonicalized by sorting the
       endpoint pair so A↔B and B↔A map to the same bucket).
    2. Within each flow, sort each direction by TCP sequence number.
    3. Deduplicate retransmissions by tracking the highest seen sequence
       end-point for each direction.
    4. Concatenate the ordered payloads into client_data / server_data.

    Returns
    -------
    list[TCPStream]
        One TCPStream per unique bidirectional TCP connection.
    """
    # Group by canonical flow (smaller endpoint first)
    flow_buckets: dict[tuple, list[RawSegment]] = defaultdict(list)
    for seg in segments:
        key = _canonical_key(seg.src_ip, seg.src_port, seg.dst_ip, seg.dst_port)
        flow_buckets[key].append(seg)

    streams: list[TCPStream] = []
    for key, segs in flow_buckets.items():
        stream = _reassemble_flow(key, segs)
        streams.append(stream)

    logger.debug("Reassembled %d TCP streams from %d segments", len(streams), len(segments))
    return streams


def _canonical_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> tuple:
    """Return a stable bidirectional key by always putting the lower endpoint first."""
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    return (min(a, b), max(a, b))


import re

_MAIL_SERVER_PORTS = {25, 465, 587, 143, 993, 110, 995, 2525}

_SERVER_BANNERS = (
    re.compile(rb"^220[ -]", re.MULTILINE),
    re.compile(rb"^\* OK\b", re.MULTILINE | re.IGNORECASE),
    re.compile(rb"^\+OK\b", re.MULTILINE),
)

_CLIENT_COMMANDS = (
    re.compile(rb"^(?:EHLO|HELO)\b", re.MULTILINE | re.IGNORECASE),
    re.compile(rb"^\*?\s*(?:CAPABILITY|STARTTLS|STLS)\b", re.MULTILINE | re.IGNORECASE),
    re.compile(rb"^[a-zA-Z0-9]+\s+(?:CAPABILITY|STARTTLS|LOGIN|AUTHENTICATE|SELECT)\b", re.MULTILINE | re.IGNORECASE),
    re.compile(rb"^(?:USER|PASS|QUIT|STAT|LIST|RETR)\b", re.MULTILINE | re.IGNORECASE),
)


def _identify_client_server_endpoints(
    segs: list[RawSegment]
) -> tuple[tuple[str, int], tuple[str, int]]:
    """
    Determine (client_endpoint, server_endpoint) consistently as:
    Client IP:Port -> Mail Server IP:Port.

    Preserves original packet directions within the segments list.
    """
    first = min(segs, key=lambda s: (s.timestamp, s.packet_number))
    ep1 = (first.src_ip, first.src_port)
    ep2 = (first.dst_ip, first.dst_port)

    # 1. Check well-known mail server ports
    ep1_is_server_port = ep1[1] in _MAIL_SERVER_PORTS
    ep2_is_server_port = ep2[1] in _MAIL_SERVER_PORTS

    if ep2_is_server_port and not ep1_is_server_port:
        return ep1, ep2
    if ep1_is_server_port and not ep2_is_server_port:
        return ep2, ep1

    # 2. Check server greeting banners vs client commands across segments
    ep1_payload = b"".join(s.data for s in segs if (s.src_ip, s.src_port) == ep1)[:2048]
    ep2_payload = b"".join(s.data for s in segs if (s.src_ip, s.src_port) == ep2)[:2048]

    ep1_has_banner = any(p.search(ep1_payload) for p in _SERVER_BANNERS)
    ep2_has_banner = any(p.search(ep2_payload) for p in _SERVER_BANNERS)

    if ep1_has_banner and not ep2_has_banner:
        return ep2, ep1  # ep1 is server, ep2 is client
    if ep2_has_banner and not ep1_has_banner:
        return ep1, ep2  # ep2 is server, ep1 is client

    ep1_has_client_cmd = any(p.search(ep1_payload) for p in _CLIENT_COMMANDS)
    ep2_has_client_cmd = any(p.search(ep2_payload) for p in _CLIENT_COMMANDS)

    if ep1_has_client_cmd and not ep2_has_client_cmd:
        return ep1, ep2
    if ep2_has_client_cmd and not ep1_has_client_cmd:
        return ep2, ep1

    # 3. Fallback: initiator of first segment is treated as client
    return ep1, ep2


def _reassemble_flow(
    canonical_key: tuple, segs: list[RawSegment]
) -> TCPStream:
    """Reassemble one bidirectional flow normalized as Client -> Server."""
    client_ep, server_ep = _identify_client_server_endpoints(segs)
    client_ip, client_port = client_ep
    server_ip, server_port = server_ep

    client_segs = [s for s in segs if s.src_ip == client_ip and s.src_port == client_port]
    server_segs = [s for s in segs if s.src_ip == server_ip and s.src_port == server_port]

    client_data = _assemble_direction(client_segs)
    server_data = _assemble_direction(server_segs)

    # Combined chronological view (interleaved by timestamp) for sniffing
    all_segs_sorted = sorted(segs, key=lambda s: (s.timestamp, s.packet_number))
    combined = b"".join(s.data for s in all_segs_sorted)

    all_packet_nums = sorted({s.packet_number for s in segs})
    stream_key = f"{client_ip}:{client_port}-{server_ip}:{server_port}"

    return TCPStream(
        stream_key=stream_key,
        src_ip=client_ip,
        dst_ip=server_ip,
        src_port=client_port,
        dst_port=server_port,
        client_data=client_data,
        server_data=server_data,
        combined_data=combined,
        segments=segs,
        first_packet=all_packet_nums[0] if all_packet_nums else 0,
        last_packet=all_packet_nums[-1] if all_packet_nums else 0,
    )


def _assemble_direction(segs: list[RawSegment]) -> bytes:
    """
    Sort by sequence number and merge, deduplicating retransmissions.

    This is a simplified reassembler.  For most email captures (which are
    low-volume) a full SACK-aware reassembler is not necessary, but we do
    handle simple retransmit overlap.
    """
    if not segs:
        return b""

    sorted_segs = sorted(segs, key=lambda s: (s.byte_offset, s.packet_number))

    # Merge by tracking the current write frontier
    buf = bytearray()
    frontier = sorted_segs[0].byte_offset  # initial seq of first segment

    for seg in sorted_segs:
        seg_start = seg.byte_offset
        seg_end = seg_start + len(seg.data)

        if seg_start > frontier:
            # Gap: fill with zeros (indicates packet loss in capture)
            gap = seg_start - frontier
            if gap < 65536:  # sanity limit
                buf.extend(b"\x00" * gap)
            frontier = seg_start

        # Overlap / retransmit — advance only the new bytes
        new_start = max(seg_start, frontier) - seg_start
        if new_start < len(seg.data):
            buf.extend(seg.data[new_start:])
            frontier = max(frontier, seg_end)

    return bytes(buf)
