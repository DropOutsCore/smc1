"""
securemailscope/ingestion/pcap_reader.py
------------------------------------------
Pure-Python libpcap file reader — no external dependencies.

Used as a fallback when both Scapy and pyshark are unavailable,
or when they fail to parse a file.

Supports libpcap global header magic 0xa1b2c3d4 (little-endian)
and 0xd4c3b2a1 (big-endian), plus pcapng format detection.

FORENSIC CONSTRAINT: Read-only ('rb') access only.
"""

from __future__ import annotations

import struct
import logging
from typing import Generator

logger = logging.getLogger(__name__)

_MAGIC_LE = 0xA1B2C3D4
_MAGIC_BE = 0xD4C3B2A1
_MAGIC_NS_LE = 0xA1B23C4D   # nanosecond precision
_MAGIC_NS_BE = 0x4D3CB2A1
_PCAPNG_MAGIC = 0x0A0D0D0A


def _parse_ip_and_tcp(frame: bytes, link_type: int) -> tuple | None:
    """
    Parse an Ethernet/raw-IP frame and extract TCP metadata.

    Returns (src_ip, dst_ip, src_port, dst_port, seq, payload) or None.
    """
    try:
        pos = 0

        # Ethernet (link_type=1) or Linux cooked (link_type=113)
        if link_type == 1:  # Ethernet
            if len(frame) < 14:
                return None
            ethertype = struct.unpack("!H", frame[12:14])[0]
            if ethertype == 0x8100:  # VLAN tagged
                ethertype = struct.unpack("!H", frame[16:18])[0]
                pos = 18
            else:
                pos = 14
            if ethertype != 0x0800:  # IPv4 only
                return None
        elif link_type == 228:  # Raw IPv4
            pos = 0
        elif link_type == 101:  # Raw IPv4 (alt)
            pos = 0
        else:
            return None

        # IPv4
        if len(frame) < pos + 20:
            return None
        ihl = (frame[pos] & 0x0F) * 4
        protocol = frame[pos + 9]
        if protocol != 6:  # TCP only
            return None
        src_ip = ".".join(str(b) for b in frame[pos + 12: pos + 16])
        dst_ip = ".".join(str(b) for b in frame[pos + 16: pos + 20])
        ip_end = pos + ihl

        # TCP
        if len(frame) < ip_end + 20:
            return None
        src_port = struct.unpack("!H", frame[ip_end: ip_end + 2])[0]
        dst_port = struct.unpack("!H", frame[ip_end + 2: ip_end + 4])[0]
        seq = struct.unpack("!I", frame[ip_end + 4: ip_end + 8])[0]
        tcp_data_offset = ((frame[ip_end + 12] >> 4) & 0xF) * 4
        payload_start = ip_end + tcp_data_offset
        payload = frame[payload_start:]
        return src_ip, dst_ip, src_port, dst_port, seq, payload
    except Exception:
        return None


def iter_pcap_tcp(path: str) -> Generator[tuple, None, None]:
    """
    Iterate over TCP segments in a libpcap file.

    Yields (packet_number, timestamp, src_ip, dst_ip, src_port, dst_port, seq, payload).
    """
    with open(path, "rb") as f:
        # Read global header (24 bytes)
        gh = f.read(24)
        if len(gh) < 24:
            logger.warning("File too short to be a valid PCAP: %s", path)
            return

        magic = struct.unpack("<I", gh[:4])[0]
        if magic in (_MAGIC_LE, _MAGIC_NS_LE):
            byte_order = "<"
        elif magic in (_MAGIC_BE, _MAGIC_NS_BE):
            byte_order = ">"
        elif magic == _PCAPNG_MAGIC:
            logger.warning("pcapng format detected — use Scapy or pyshark for pcapng support")
            return
        else:
            logger.warning("Unknown PCAP magic: 0x%08X", magic)
            return

        link_type = struct.unpack(f"{byte_order}I", gh[20:24])[0]
        packet_num = 0

        while True:
            rec_hdr = f.read(16)
            if not rec_hdr:
                break
            if len(rec_hdr) < 16:
                break

            ts_sec = struct.unpack(f"{byte_order}I", rec_hdr[0:4])[0]
            ts_usec = struct.unpack(f"{byte_order}I", rec_hdr[4:8])[0]
            incl_len = struct.unpack(f"{byte_order}I", rec_hdr[8:12])[0]

            frame = f.read(incl_len)
            if len(frame) < incl_len:
                break

            packet_num += 1
            timestamp = ts_sec + ts_usec / 1_000_000.0

            result = _parse_ip_and_tcp(frame, link_type)
            if result is None:
                continue

            src_ip, dst_ip, src_port, dst_port, seq, payload = result
            if not payload:
                continue

            yield packet_num, timestamp, src_ip, dst_ip, src_port, dst_port, seq, payload
