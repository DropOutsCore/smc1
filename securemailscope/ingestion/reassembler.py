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


def _reassemble_flow(
    canonical_key: tuple, segs: list[RawSegment]
) -> TCPStream:
    """Reassemble one bidirectional flow."""
    # Determine the "client" side as the initiator (first segment's source)
    first = min(segs, key=lambda s: (s.timestamp, s.packet_number))
    client_ip, client_port = first.src_ip, first.src_port
    server_ip, server_port = first.dst_ip, first.dst_port

    client_segs = [s for s in segs if s.src_ip == client_ip and s.src_port == client_port]
    server_segs = [s for s in segs if not (s.src_ip == client_ip and s.src_port == client_port)]

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
