"""
securemailscope/tests/test_evidence_layer.py
--------------------------------------------
Unit tests for the non-invasive forensic evidence layer and chain of custody.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import pytest

from securemailscope.forensics.evidence_layer import (
    INTEGRITY_STATEMENT,
    PASSIVE_OFFLINE_STATUS,
    ForensicEvidenceWrapper,
    attach_finding_evidence,
    calculate_pcap_sha256,
    enrich_report_with_forensics,
)


def test_calculate_pcap_sha256_readonly(tmp_path: Path):
    """Ensure SHA-256 calculation is read-only and never alters the source file."""
    pcap_file = tmp_path / "test_sample.pcap"
    original_bytes = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 32
    pcap_file.write_bytes(original_bytes)

    mtime_before = os.path.getmtime(pcap_file)
    size_before = os.path.getsize(pcap_file)

    sha = calculate_pcap_sha256(pcap_file)
    assert len(sha) == 64
    assert sha == hashlib.sha256(original_bytes).hexdigest()

    # Verify original file was strictly unmodified
    assert pcap_file.read_bytes() == original_bytes
    assert os.path.getmtime(pcap_file) == mtime_before
    assert os.path.getsize(pcap_file) == size_before


def test_attach_finding_evidence_chain():
    """Verify evidence reference chain: PCAP SHA-256 → Session → Packet #/Offset → Observed Value → Finding ID → Rule."""
    session = {
        "session_id": "sess-xyz-1234",
        "protocol": "SMTP",
        "src_ip": "10.0.1.20",
        "dst_ip": "198.51.100.5",
        "src_port": 55001,
        "dst_port": 25,
        "tls_version": "TLS1.0",
        "cipher_suite": "TLS_RSA_WITH_AES_128_CBC_SHA",
        "pfs": False,
        "packet_refs": [8, 9, 10],
    }

    finding = {
        "id": "deprecated-tls-10",
        "finding_id": "f6e9250e-b111-427f-81a7-bb7c1793d445",
        "category": "deprecated-protocol",
        "severity": "high",
        "description": "TLS 1.0 is negotiated — deprecated by NIST and IETF",
        "evidence_ref": {"packet_number": 8, "byte_offset": 0},
    }

    pcap_sha = "0c96a199e6790537cec5f73b0d9b9730e0852bb8e22eadc8bd0320f8605e7ddc"
    ev = attach_finding_evidence(finding, session, pcap_sha)

    assert ev["pcap_sha256"] == pcap_sha
    assert ev["session_id"] == "sess-xyz-1234"
    assert ev["session_flow"] == "SMTP 10.0.1.20:55001 → 198.51.100.5:25"
    assert ev["packet_number"] == 8
    assert ev["byte_offset"] == 0
    assert "TLS1.0" in ev["observed_value"]
    assert ev["finding_id"] == "f6e9250e-b111-427f-81a7-bb7c1793d445"
    assert ev["detection_rule"] == "deprecated-tls-10"

    # Check that formatted chain contains all 6 elements
    chain = ev["evidence_chain"]
    assert "0c96a199e679" in chain
    assert "SMTP 10.0.1.20:55001 → 198.51.100.5:25" in chain
    assert "Pkt #8" in chain
    assert "Offset 0" in chain
    assert "Observed: TLS Version: TLS1.0" in chain
    assert "f6e9250e" in chain
    assert "Rule: deprecated-tls-10" in chain


def test_enrich_report_with_forensics_integrity():
    """Verify that enrich_report_with_forensics adds required forensic section and integrity statement."""
    mock_report = {
        "report_id": "rep-abc-001",
        "source_pcap_path": "C:\\test\\mail.pcap",
        "source_pcap_sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "generated_at": "2026-09-29T20:00:00Z",
        "tool_version": "1.0.0",
        "hosts": [
            {
                "host": "198.51.100.25:25",
                "posture_grade": "A",
                "sessions": [
                    {
                        "session_id": "sess-100",
                        "protocol": "SMTP",
                        "src_ip": "10.0.0.1",
                        "src_port": 40000,
                        "dst_ip": "198.51.100.25",
                        "dst_port": 25,
                        "tls_version": "TLS1.3",
                        "cipher_suite": "TLS_AES_256_GCM_SHA384",
                        "findings": [
                            {
                                "id": "clean-tls",
                                "finding_id": "f-1",
                                "category": "info",
                                "severity": "low",
                                "description": "Clean TLS 1.3 session",
                                "evidence_ref": {"packet_number": 3},
                            }
                        ],
                    }
                ],
            }
        ],
    }

    wrapper = ForensicEvidenceWrapper()
    enriched = wrapper.enrich(mock_report, analysis_id="analysis-custom-999")

    assert enriched["analysis_id"] == "analysis-custom-999"
    assert enriched["report_id"] == "rep-abc-001"
    assert enriched["source_filename"] == "mail.pcap"

    sec = enriched["forensic_evidence_and_chain_of_custody"]
    assert sec is not None
    assert sec["source_pcap"] == "C:\\test\\mail.pcap"
    assert sec["pcap_sha256"] == "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    assert sec["analysis_id"] == "analysis-custom-999"
    assert sec["report_id"] == "rep-abc-001"
    assert sec["analyzer_version"] == "1.0.0"
    assert sec["integrity_statement"] == INTEGRITY_STATEMENT
    assert INTEGRITY_STATEMENT == "No active network connections were made during analysis."
    assert "AIR-GAPPED" in sec["passive_offline_status"].upper()

    mappings = sec["packet_level_evidence_mapping"]
    assert len(mappings) == 1
    assert mappings[0]["packet_number"] == 3
    assert mappings[0]["detection_rule"] == "clean-tls"
