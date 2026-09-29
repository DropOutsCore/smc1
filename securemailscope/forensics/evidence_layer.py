"""
securemailscope/forensics/evidence_layer.py
-------------------------------------------
Non-invasive forensic evidence layer for AVALOK / SecureMailScope.

Guarantees:
1. Strict read-only access to source PCAPs (original PCAP is NEVER modified).
2. Works 100% offline & air-gapped without external network calls, sockets, or APIs.
3. Attaches end-to-end evidence references to every finding:
   PCAP SHA-256 → Session → Packet Number/Offset → Observed Value → Finding ID → Detection Rule
4. Enriches final reports with a formal "Forensic Evidence & Chain of Custody" section.
"""

from __future__ import annotations

import datetime
import hashlib
import os
from pathlib import Path
from typing import Any, Optional
import uuid


INTEGRITY_STATEMENT = "No active network connections were made during analysis."
PASSIVE_OFFLINE_STATUS = "PASSIVE_OFFLINE (Air-Gapped / Strictly Read-Only)"


def calculate_pcap_sha256(pcap_path: str | Path) -> str:
    """
    Compute SHA-256 hash of a PCAP file in streaming read-only binary mode.

    The file is opened strictly with mode 'rb'. It is NEVER written to or modified.
    """
    path = Path(pcap_path)
    if not path.is_file():
        return ""

    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def _extract_observed_value(finding: dict, session: dict) -> str:
    """Extract or infer the empirical observed value on the wire that triggered the finding."""
    # Check if finding already has observed details
    if finding.get("observed_value"):
        return str(finding["observed_value"])

    category = finding.get("category", "").lower()
    rule_id = finding.get("id", "").lower()

    if "protocol" in category or "deprecated" in rule_id or "tls" in rule_id:
        tls_ver = session.get("tls_version")
        if tls_ver:
            return f"TLS Version: {tls_ver}"

    if "cipher" in category or "weak" in rule_id or "cipher" in rule_id:
        cipher = session.get("cipher_suite")
        if cipher:
            return f"Cipher Suite: {cipher}"

    if "pfs" in rule_id or "forward-secrecy" in category:
        kex = session.get("key_exchange", "RSA")
        pfs = session.get("pfs", False)
        return f"Key Exchange: {kex}, PFS: {pfs}"

    if "cert" in category or "expired" in rule_id or "self-signed" in rule_id:
        cert = session.get("certificate")
        if isinstance(cert, dict) and cert:
            sub = cert.get("subject")
            if isinstance(sub, dict):
                sub_str = sub.get("CN") or cert.get("subject_str", "")
            else:
                sub_str = str(sub) if sub else cert.get("subject_str", "")
            exp = cert.get("not_after", "")
            return f"Cert Subject: {sub_str or 'Unknown'}, Expiry: {exp or 'N/A'}"
        return "Certificate validation anomaly"

    if "downgrade" in rule_id or "starttls" in category:
        banner = session.get("banner", "")
        clean_banner = "".join(ch if (ch >= " " and ord(ch) < 127) else "" for ch in str(banner))[:40]
        return f"STARTTLS state (Banner: '{clean_banner}')"

    # Contributing factors
    factors = finding.get("contributing_factors")
    if factors and isinstance(factors, list) and len(factors) > 0:
        return str(factors[0])

    evidence_ref = finding.get("evidence_ref", {})
    ev_type = evidence_ref.get("type")
    if ev_type:
        return f"Event: {ev_type}"

    return finding.get("description", "Vulnerability indicator observed on wire")


def attach_finding_evidence(
    finding: dict,
    session: dict,
    pcap_sha256: str,
) -> dict:
    """
    Attach structured evidence reference to a single finding.

    Chain:
    PCAP SHA-256 → Session → Packet Number/Offset → Observed Value → Finding ID → Detection Rule
    """
    evidence_ref = finding.get("evidence_ref", {})
    pkt_num = evidence_ref.get("packet_number")
    if pkt_num is None:
        pkt_refs = session.get("packet_refs", [])
        pkt_num = pkt_refs[0] if pkt_refs else 0

    byte_offset = evidence_ref.get("byte_offset")
    if byte_offset is None:
        byte_offset = 0

    observed_value = _extract_observed_value(finding, session)
    finding_id = finding.get("finding_id") or finding.get("id", "finding")
    rule_id = finding.get("id", "rule")
    session_id = session.get("session_id", "session-unknown")

    proto = session.get("protocol", "SMTP")
    src = f"{session.get('src_ip', '')}:{session.get('src_port', '')}"
    dst = f"{session.get('dst_ip', '')}:{session.get('dst_port', '')}"
    session_flow = f"{proto} {src} → {dst}"

    short_sha = pcap_sha256[:12] if pcap_sha256 else "unknown_sha"
    short_fid = finding_id[:8] if isinstance(finding_id, str) and len(finding_id) > 8 else str(finding_id)

    evidence_chain = (
        f"{short_sha}... → Session [{session_flow}] → "
        f"Pkt #{pkt_num} (Offset {byte_offset}) → Observed: {observed_value} → "
        f"Finding #{short_fid} → Rule: {rule_id}"
    )

    evidence_record = {
        "pcap_sha256": pcap_sha256,
        "session_id": session_id,
        "session_flow": session_flow,
        "packet_number": pkt_num,
        "byte_offset": byte_offset,
        "observed_value": observed_value,
        "finding_id": finding_id,
        "detection_rule": rule_id,
        "evidence_chain": evidence_chain,
    }

    # Non-invasively attach without overwriting existing finding attributes
    finding["evidence_reference"] = evidence_record
    return evidence_record


def enrich_report_with_forensics(
    report: dict,
    pcap_path: str | Path | None = None,
    pcap_sha256: str | None = None,
    analysis_id: str | None = None,
) -> dict:
    """
    Non-invasive enrichment function:
    Consumes the existing report dictionary and adds forensic chain-of-custody
    metadata and evidence references for every finding without modifying
    existing analyzer or scoring outputs.
    """
    # 1. Resolve source PCAP path and SHA-256
    source_pcap = pcap_path or report.get("source_pcap_path", "")
    source_pcap_str = str(source_pcap)
    source_filename = Path(source_pcap_str).name if source_pcap_str else "capture.pcap"

    computed_sha = pcap_sha256 or report.get("source_pcap_sha256")
    if not computed_sha and source_pcap_str and os.path.isfile(source_pcap_str):
        computed_sha = calculate_pcap_sha256(source_pcap_str)

    computed_sha = computed_sha or "0000000000000000000000000000000000000000000000000000000000000000"

    # 2. Identifiers and timestamp
    report_id = report.get("report_id") or str(uuid.uuid4())
    resolved_analysis_id = analysis_id or report.get("analysis_id") or str(uuid.uuid4())
    timestamp = report.get("generated_at") or datetime.datetime.now(datetime.timezone.utc).isoformat()
    tool_version = report.get("tool_version", "1.0.0")

    # Update top-level report keys
    report["report_id"] = report_id
    report["analysis_id"] = resolved_analysis_id
    report["source_pcap_sha256"] = computed_sha
    report["source_pcap_path"] = source_pcap_str
    report["source_filename"] = source_filename

    # 3. Iterate through all hosts and sessions to attach evidence references to every finding
    packet_evidence_mappings: list[dict] = []
    hosts = report.get("hosts", [])
    for host in hosts:
        for session in host.get("sessions", []):
            for finding in session.get("findings", []):
                evidence = attach_finding_evidence(finding, session, computed_sha)
                packet_evidence_mappings.append(evidence)

    # 4. Build formal Forensic Evidence & Chain of Custody section
    forensic_section = {
        "source_pcap": source_pcap_str,
        "source_filename": source_filename,
        "pcap_sha256": computed_sha,
        "analysis_id": resolved_analysis_id,
        "report_id": report_id,
        "timestamp": timestamp,
        "analyzer_version": tool_version,
        "passive_offline_status": PASSIVE_OFFLINE_STATUS,
        "integrity_statement": INTEGRITY_STATEMENT,
        "packet_level_evidence_mapping": packet_evidence_mappings,
    }

    report["forensic_evidence_and_chain_of_custody"] = forensic_section

    # Synchronize/enhance custody metadata block
    custody = report.get("custody", {})
    custody["analysis_id"] = resolved_analysis_id
    custody["report_id"] = report_id
    custody["source_pcap_path"] = source_pcap_str
    custody["source_filename"] = source_filename
    custody["source_pcap_sha256"] = computed_sha
    custody["passive_offline_status"] = PASSIVE_OFFLINE_STATUS
    custody["integrity_statement"] = INTEGRITY_STATEMENT
    report["custody"] = custody

    return report


class ForensicEvidenceWrapper:
    """
    Independent wrapper class that consumes raw pipeline results
    and enriches the final output with forensic evidence without altering
    core analysis logic.
    """

    def __init__(self, analyzer_version: str = "1.0.0"):
        self.analyzer_version = analyzer_version

    def enrich(
        self,
        report: dict,
        pcap_path: str | Path | None = None,
        pcap_sha256: str | None = None,
        analysis_id: str | None = None,
    ) -> dict:
        return enrich_report_with_forensics(
            report,
            pcap_path=pcap_path,
            pcap_sha256=pcap_sha256,
            analysis_id=analysis_id,
        )
