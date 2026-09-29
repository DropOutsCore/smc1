"""
securemailscope/forensics/custody.py
---------------------------------------
Chain-of-custody metadata and hashing.

Key differentiator — every report includes:
  1. SHA-256 of the source PCAP (computed on load, read-only access)
  2. SHA-256 of the generated report itself
  3. Every Finding.evidence_ref resolves to a specific packet number
     and (where available) byte offset in the original PCAP

CONSTRAINT: The source PCAP is NEVER written to or modified.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import platform
import socket
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class CustodyMetadata:
    """Chain-of-custody record attached to every generated report."""
    report_id: str
    source_pcap_path: str
    source_pcap_sha256: str
    source_pcap_size_bytes: int
    generated_at: str                # ISO 8601
    analyst_host: str = ""
    analyst_platform: str = ""
    tool_version: str = "1.0.0"
    report_sha256: Optional[str] = None   # filled in after report is generated

    def to_dict(self) -> dict:
        return {
            "report_id": self.report_id,
            "source_pcap_path": self.source_pcap_path,
            "source_pcap_sha256": self.source_pcap_sha256,
            "source_pcap_size_bytes": self.source_pcap_size_bytes,
            "generated_at": self.generated_at,
            "analyst_host": self.analyst_host,
            "analyst_platform": self.analyst_platform,
            "tool_version": self.tool_version,
            "report_sha256": self.report_sha256,
        }


# Optional is not imported at top to avoid circular imports
from typing import Optional  # noqa: E402


def build_custody_metadata(
    pcap_path: str,
    pcap_sha256: str,
    pcap_size: int,
) -> CustodyMetadata:
    """Create a CustodyMetadata record for this analysis run."""
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "unknown"

    return CustodyMetadata(
        report_id=str(uuid.uuid4()),
        source_pcap_path=os.path.abspath(pcap_path),
        source_pcap_sha256=pcap_sha256,
        source_pcap_size_bytes=pcap_size,
        generated_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        analyst_host=hostname,
        analyst_platform=platform.platform(),
    )


def hash_report(report_content: str | bytes) -> str:
    """
    Compute SHA-256 of the generated report content.

    Called after the report is serialised so the hash reflects the
    final output, including the source PCAP hash.
    """
    if isinstance(report_content, str):
        report_content = report_content.encode("utf-8")
    return hashlib.sha256(report_content).hexdigest()
