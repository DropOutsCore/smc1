"""
securemailscope/ingestion/models.py
------------------------------------
Data-classes shared across the ingestion pipeline.

FORENSIC NOTE: The source PCAP is always opened read-only ('rb').  No
write/modify operations are ever performed on the source file — this is
enforced structurally by the loader (see loader.py).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ProtocolType(str, Enum):
    SMTP = "SMTP"
    IMAP = "IMAP"
    POP3 = "POP3"
    UNKNOWN = "UNKNOWN"


@dataclass
class RawSegment:
    """A single TCP payload segment with forensic references."""
    packet_number: int     # 1-indexed packet number in the PCAP
    byte_offset: int       # byte offset within the TCP stream (0-indexed)
    data: bytes
    timestamp: float       # epoch seconds
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int


@dataclass
class TCPStream:
    """
    A reassembled, bidirectional TCP stream.

    client_data / server_data are the ordered, deduplicated payloads seen
    from each side.  segment_refs lets us trace any byte range back to
    the originating packet number for chain-of-custody.
    """
    stream_key: str           # "{src_ip}:{src_port}-{dst_ip}:{dst_port}"
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    client_data: bytes = field(default_factory=bytes)
    server_data: bytes = field(default_factory=bytes)
    # combined chronological payload (for protocol sniffing)
    combined_data: bytes = field(default_factory=bytes)
    segments: list[RawSegment] = field(default_factory=list)
    first_packet: int = 0    # packet number of SYN / first payload
    last_packet: int = 0


@dataclass
class StarttlsResult:
    """Outcome of STARTTLS negotiation detection."""
    detected: bool = False
    command_packet: Optional[int] = None     # packet that carried STARTTLS command
    response_packet: Optional[int] = None   # packet that carried 220 Ready / OK
    starttls_offset: Optional[int] = None   # byte offset in stream where TLS begins
    downgrade_suspected: bool = False       # plaintext continued past STARTTLS
    downgrade_evidence_packet: Optional[int] = None


@dataclass
class EmailSession:
    """
    Fully reconstructed email session.

    packet_refs lists every packet number involved in this session; this
    list is what makes findings forensically traceable to the source file.
    """
    session_id: str
    protocol: str                          # SMTP | IMAP | POP3
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    stream: TCPStream
    starttls_detected: bool = False
    starttls_offset: Optional[int] = None  # byte in stream where TLS begins
    downgrade_suspected: bool = False
    downgrade_evidence_packet: Optional[int] = None
    is_implicit_tls: bool = False          # True for 465/993/995
    banner: str = ""                       # server greeting / banner text
    packet_refs: list[int] = field(default_factory=list)

    @property
    def host_key(self) -> str:
        """Canonical identifier for the destination mail server."""
        return f"{self.dst_ip}:{self.dst_port}"


@dataclass
class PcapMetadata:
    """Forensic metadata for the source capture file."""
    path: str
    sha256: str
    file_size_bytes: int
    packet_count: int
    capture_start: Optional[float] = None
    capture_end: Optional[float] = None

    @staticmethod
    def from_path(path: str) -> "PcapMetadata":
        """
        Read the file in read-only binary mode and compute SHA-256.

        FORENSIC CONSTRAINT: Only 'rb' mode is ever used.  The file is
        never opened for writing.
        """
        sha256 = hashlib.sha256()
        size = 0
        with open(path, "rb") as fh:           # read-only, always
            for chunk in iter(lambda: fh.read(65536), b""):
                sha256.update(chunk)
                size += len(chunk)
        return PcapMetadata(
            path=path,
            sha256=sha256.hexdigest(),
            file_size_bytes=size,
            packet_count=0,   # filled in after parsing
        )
