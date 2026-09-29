"""securemailscope/forensics/__init__.py"""

from securemailscope.forensics.custody import CustodyMetadata, build_custody_metadata, hash_report
from securemailscope.forensics.evidence_layer import (
    INTEGRITY_STATEMENT,
    PASSIVE_OFFLINE_STATUS,
    ForensicEvidenceWrapper,
    attach_finding_evidence,
    calculate_pcap_sha256,
    enrich_report_with_forensics,
)

__all__ = [
    "CustodyMetadata",
    "build_custody_metadata",
    "hash_report",
    "INTEGRITY_STATEMENT",
    "PASSIVE_OFFLINE_STATUS",
    "ForensicEvidenceWrapper",
    "attach_finding_evidence",
    "calculate_pcap_sha256",
    "enrich_report_with_forensics",
]
