"""
securemailscope/ingestion/loader.py
-------------------------------------
PCAP loading using Scapy (primary) with a pyshark fallback.

FORENSIC CONSTRAINT: Source PCAPs are NEVER modified.  All file access
uses read-only mode.  If Scapy cannot load a file it raises an exception
rather than writing any partial data.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

from securemailscope.ingestion.models import PcapMetadata, RawSegment

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Attempt to import Scapy (primary)
# ---------------------------------------------------------------------------
try:
    from scapy.all import rdpcap, TCP, IP, IPv6, Ether
    from scapy.layers.inet import TCP as STCP
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False
    logger.warning("Scapy not available — falling back to pyshark loader.")

# ---------------------------------------------------------------------------
# Pyshark fallback
# ---------------------------------------------------------------------------
try:
    import pyshark  # type: ignore
    _PYSHARK_AVAILABLE = True
except ImportError:
    _PYSHARK_AVAILABLE = False


class PcapLoadError(RuntimeError):
    """Raised when no suitable packet parser can load the file."""


def load_pcap(path: str | Path) -> tuple[PcapMetadata, list[RawSegment]]:
    """
    Load a .pcap / .pcapng file and return per-segment metadata.

    Parameters
    ----------
    path : str | Path
        Absolute or relative path to the capture file.

    Returns
    -------
    PcapMetadata
        Forensic file metadata (SHA-256, size, …).
    list[RawSegment]
        Ordered list of TCP payload segments with forensic back-references.

    Raises
    ------
    PcapLoadError
        If neither Scapy nor pyshark can parse the file.
    FileNotFoundError
        If the file does not exist.
    """
    path = str(path)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"PCAP not found: {path}")

    logger.info("Computing SHA-256 hash of source file (read-only): %s", path)
    meta = PcapMetadata.from_path(path)
    logger.info("Source PCAP SHA-256: %s", meta.sha256)

    if _SCAPY_AVAILABLE:
        segments, count = _load_scapy(path)
        # If scapy extracted no segments (e.g., no libpcap/WinPcap installed),
        # fall back to pure-Python reader which has no system dependencies
        if not segments and count > 0:
            logger.info("Scapy extracted no segments (no libpcap?) — using pure-Python fallback")
            segments, count = _load_pure_python(path)
    elif _PYSHARK_AVAILABLE:
        segments, count = _load_pyshark(path)
    else:
        segments, count = _load_pure_python(path)

    meta.packet_count = count
    logger.info("Loaded %d packets, extracted %d TCP segments", count, len(segments))
    return meta, segments


def _load_scapy(path: str) -> tuple[list[RawSegment], int]:
    """Parse with Scapy (wraps rdpcap which reads the file in binary mode)."""
    from scapy.all import rdpcap, TCP, IP, IPv6

    logger.debug("Using Scapy to load: %s", path)
    try:
        packets = rdpcap(path)    # Scapy reads in rb mode internally
    except Exception as exc:
        raise PcapLoadError(f"Scapy failed to read '{path}': {exc}") from exc

    segments: list[RawSegment] = []
    for idx, pkt in enumerate(packets, start=1):
        try:
            if not pkt.haslayer(TCP):
                continue
            tcp = pkt[TCP]
            if not tcp.payload or len(bytes(tcp.payload)) == 0:
                continue

            ip_layer = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)

            seg = RawSegment(
                packet_number=idx,
                byte_offset=tcp.seq,
                data=bytes(tcp.payload),
                timestamp=float(pkt.time),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=int(tcp.sport),
                dst_port=int(tcp.dport),
            )
            segments.append(seg)
        except Exception as exc:  # defensive: never crash on one bad packet
            logger.debug("Skipping malformed packet %d: %s", idx, exc)

    return segments, len(packets)


def _load_pyshark(path: str) -> tuple[list[RawSegment], int]:
    """Fallback loader using pyshark (wraps tshark)."""
    import pyshark  # type: ignore

    logger.debug("Using pyshark to load: %s", path)
    try:
        cap = pyshark.FileCapture(path, display_filter="tcp", keep_packets=False)
    except Exception as exc:
        raise PcapLoadError(f"pyshark failed to open '{path}': {exc}") from exc

    segments: list[RawSegment] = []
    count = 0
    try:
        for pkt in cap:
            count += 1
            try:
                if not hasattr(pkt, "tcp") or not hasattr(pkt, "ip"):
                    continue
                tcp = pkt.tcp
                ip = pkt.ip
                payload_hex = getattr(tcp, "payload", None)
                if not payload_hex:
                    continue
                data = bytes.fromhex(payload_hex.replace(":", ""))
                if not data:
                    continue
                seg = RawSegment(
                    packet_number=count,
                    byte_offset=int(tcp.seq),
                    data=data,
                    timestamp=float(pkt.sniff_timestamp),
                    src_ip=str(ip.src),
                    dst_ip=str(ip.dst),
                    src_port=int(tcp.srcport),
                    dst_port=int(tcp.dstport),
                )
                segments.append(seg)
            except Exception as exc:
                logger.debug("Skipping pyshark packet %d: %s", count, exc)
    finally:
        cap.close()

    return segments, count


def _load_pure_python(path: str) -> tuple[list[RawSegment], int]:
    """Zero-dependency pure-Python libpcap reader."""
    from securemailscope.ingestion.pcap_reader import iter_pcap_tcp
    logger.debug("Using pure-Python pcap reader: %s", path)
    segments: list[RawSegment] = []
    count = 0
    for pkt_num, ts, src_ip, dst_ip, src_port, dst_port, seq, payload in iter_pcap_tcp(path):
        count = pkt_num
        segments.append(RawSegment(
            packet_number=pkt_num, byte_offset=seq, data=payload,
            timestamp=ts, src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port,
        ))
    return segments, count
