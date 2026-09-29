"""
securemailscope/tests/test_exporter.py
--------------------------------------
Unit tests for HTML and PDF report export.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from securemailscope.reports.exporter import to_html, to_pdf


@pytest.fixture
def sample_report_dict() -> dict:
    return {
        "report_id": "test-uuid-12345678",
        "generated_at": "2026-09-29T12:00:00Z",
        "source_pcap_path": "/path/to/capture.pcap",
        "source_pcap_sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "source_pcap_size_bytes": 1024,
        "analyst_host": "TestAnalyst",
        "tool_version": "1.0.0",
        "custody": {
            "report_id": "test-uuid-12345678",
            "report_sha256": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        },
        "tls13_visibility_note": "TLS 1.3 passive visibility note for test.",
        "hosts": [
            {
                "host": "198.51.100.25:25",
                "posture_grade": "A",
                "posture_score": 95,
                "grade_delta": "Grade A unchanged",
                "finding_summary": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 1,
                    "informational": 0,
                },
                "sessions": [
                    {
                        "session_id": "sess-1",
                        "protocol": "SMTP",
                        "src_ip": "10.0.0.1",
                        "src_port": 50000,
                        "dst_ip": "198.51.100.25",
                        "dst_port": 25,
                        "tls_version": "TLS1.3",
                        "cipher_suite": "TLS_AES_256_GCM_SHA384",
                        "pfs": True,
                        "key_exchange": "ECDHE",
                        "sni": "mail.example.com",
                        "ml_risk_label": "low",
                        "ml_confidence": 0.98,
                        "findings": [
                            {
                                "id": "test-finding-1",
                                "severity": "low",
                                "category": "informational",
                                "description": "Informational TLS 1.3 parameter verified",
                                "evidence_ref": {"packet_number": 4},
                                "cwe": "CWE-310",
                                "reference": "RFC 8446",
                                "remediation": "# Maintain TLS 1.3 settings\nssl_protocols TLSv1.3;",
                            }
                        ],
                    }
                ],
            }
        ],
    }


def test_to_html_generation(sample_report_dict: dict):
    html = to_html(sample_report_dict)
    assert isinstance(html, str)
    assert "SecureMailScope" in html
    assert "test-uuid-12345678" in html
    assert "198.51.100.25" in html


def test_to_pdf_generation(sample_report_dict: dict, tmp_path: Path):
    pdf_file = tmp_path / "test_report.pdf"
    success = to_pdf(sample_report_dict, pdf_file)
    assert success is True
    assert pdf_file.exists()
    assert pdf_file.stat().st_size > 1000

    # Verify PDF magic header
    with open(pdf_file, "rb") as f:
        header = f.read(4)
    assert header == b"%PDF"
