"""
securemailscope/tests/test_explainability.py
--------------------------------------------
Unit tests for the Explainable AI / Risk-Assessment layer in AVALOK.

Guarantees:
- Every score is explainable with transparent factor contributions.
- No fabricated contributions or black-box reasoning.
- Scoring weights are configurable rather than hard-coded.
- ML Anomaly Assessment is kept strictly separate from deterministic security findings.
"""

from __future__ import annotations

from pathlib import Path
import pytest

from securemailscope.scoring.explainability import (
    ScoringWeightConfig,
    explain_session_score,
    explain_host_score,
    enrich_report_with_explainability,
    _format_ascii_tree,
)
from securemailscope.scoring.grader import (
    score_to_intuitive_grade,
    generate_why_this_grade,
    compute_host_grade,
    PostureGradeConfig,
    PostureGradeThreshold,
    GRADE_LABELS,
)
from securemailscope.reports.exporter import to_html, to_pdf


@pytest.fixture
def sample_session_with_findings():
    return {
        "session_id": "sess-smtp-001",
        "protocol": "SMTP",
        "src_ip": "192.168.1.50",
        "dst_ip": "198.51.100.25",
        "src_port": 49152,
        "dst_port": 25,
        "tls_version": "TLS 1.0",
        "cipher_suite": "TLS_RSA_WITH_RC4_128_MD5",
        "pfs": False,
        "key_exchange": "RSA",
        "starttls_detected": True,
        "is_implicit_tls": False,
        "ml_risk_label": "high",
        "ml_confidence": 0.88,
        "anomaly_detected": True,
        "anomaly_score": 0.042,
        "findings": [
            {
                "id": "deprecated-tls-10",
                "finding_id": "find-001",
                "severity": "critical",
                "category": "Protocol Version",
                "description": "Deprecated TLS 1.0 protocol negotiated",
                "evidence_ref": {"packet_number": 14, "byte_offset": 0},
                "evidence_reference": {
                    "packet_number": 14,
                    "byte_offset": 0,
                    "observed_value": "TLS 1.0 (0x0301)",
                    "evidence_chain": "PCAP-SHA256 -> Sess-1 -> Pkt #14 -> TLS 1.0",
                },
            },
            {
                "id": "weak-cipher",
                "finding_id": "find-002",
                "severity": "high",
                "category": "Cipher Security",
                "description": "Insecure RC4/MD5 cipher suite negotiated",
                "evidence_ref": {"packet_number": 14, "byte_offset": 64},
                "evidence_reference": {
                    "packet_number": 14,
                    "byte_offset": 64,
                    "observed_value": "TLS_RSA_WITH_RC4_128_MD5",
                    "evidence_chain": "PCAP-SHA256 -> Sess-1 -> Pkt #14 -> Cipher",
                },
            },
            {
                "id": "no-pfs",
                "finding_id": "find-003",
                "severity": "medium",
                "category": "Forward Secrecy",
                "description": "No Perfect Forward Secrecy; static RSA key exchange",
                "evidence_ref": {"packet_number": 14, "byte_offset": 72},
                "evidence_reference": {
                    "packet_number": 14,
                    "byte_offset": 72,
                    "observed_value": "PFS=False (RSA)",
                    "evidence_chain": "PCAP-SHA256 -> Sess-1 -> Pkt #14 -> PFS",
                },
            },
        ],
    }


def test_explain_session_score_factors(sample_session_with_findings):
    """Test mapping each contributing feature/finding to transparent score contributions."""
    result = explain_session_score(sample_session_with_findings)

    assert "risk_score" in result
    assert "contributing_factors" in result
    assert "ascii_tree" in result
    assert "ml_anomaly_assessment" in result

    # Config default weights: deprecated-tls-10 (40) + weak-cipher (25) + no-pfs (10) = 75
    assert result["risk_score"] == 75
    assert result["severity"] == "critical"
    assert len(result["contributing_factors"]) == 3

    f1 = result["contributing_factors"][0]
    assert f1["feature"] == "TLS Protocol Version"
    assert f1["observed_value"] == "TLS 1.0 (0x0301)"
    assert f1["score_contribution"] == 40
    assert f1["severity"] == "critical"
    assert "Packet #14" in f1["evidence_reference"]
    assert "RFC 8996" in f1["short_explanation"]

    f2 = result["contributing_factors"][1]
    assert f2["feature"] == "Cipher Suite Security"
    assert f2["score_contribution"] == 25
    assert f2["severity"] == "high"

    f3 = result["contributing_factors"][2]
    assert f3["feature"] == "Forward Secrecy (PFS)"
    assert f3["score_contribution"] == 10
    assert f3["severity"] == "medium"


def test_explain_session_ascii_tree(sample_session_with_findings):
    """Verify ASCII decision tree matches standard human-readable format."""
    result = explain_session_score(sample_session_with_findings)
    tree = result["ascii_tree"]

    assert "Session Risk Score: 75 / 100" in tree
    assert "Severity: CRITICAL" in tree
    assert "WHY?" in tree
    assert "├──" in tree
    assert "└──" in tree
    assert "Total" in tree


def test_ml_anomaly_assessment_isolation(sample_session_with_findings):
    """ML anomaly assessment must be strictly separated from deterministic security findings."""
    result = explain_session_score(sample_session_with_findings)
    ml = result["ml_anomaly_assessment"]

    assert ml["is_model_anomaly"] is True
    assert ml["ml_risk_label"] == "high"
    assert ml["ml_confidence"] == 0.88
    assert "does not inflate deterministic rule scores" in ml["score_isolation_note"]

    # Verify ML is not in deterministic contributing_factors
    for factor in result["contributing_factors"]:
        assert "ml" not in factor["rule_id"].lower()


def test_configurable_scoring_weights(sample_session_with_findings):
    """Verify scoring weights can be configured rather than being hardcoded."""
    custom_config = ScoringWeightConfig(
        rule_weights={
            "deprecated-tls-10": 50,
            "weak-cipher": 35,
            "no-pfs": 15,
        }
    )
    result = explain_session_score(sample_session_with_findings, config=custom_config)

    # 50 + 35 + 15 = 100
    assert result["risk_score"] == 100
    assert result["contributing_factors"][0]["score_contribution"] == 50
    assert result["contributing_factors"][1]["score_contribution"] == 35
    assert result["contributing_factors"][2]["score_contribution"] == 15


def test_enrich_report_with_explainability(sample_session_with_findings):
    """Test full report enrichment with explainability layer."""
    report = {
        "report_id": "test-rep-001",
        "hosts": [
            {
                "host": "mail.example.org",
                "posture_score": 75,
                "posture_grade": "C",
                "sessions": [sample_session_with_findings],
            }
        ],
    }

    enriched = enrich_report_with_explainability(report)

    assert "explainability" in enriched
    assert enriched["explainability"]["status"] == "EXPLAINABLE_AI_RISK_ASSESSMENT_ACTIVE"
    assert enriched["explainability"]["total_factors_evaluated"] == 3

    host = enriched["hosts"][0]
    assert "why_this_score" in host
    assert host["why_this_score"]["posture_score"] == 75
    assert len(host["why_this_score"]["contributing_factors"]) == 3

    sess = host["sessions"][0]
    assert "why_this_score" in sess
    assert "ml_anomaly_assessment" in sess


def test_html_and_pdf_export_with_explainability(sample_session_with_findings, tmp_path):
    """Test HTML and PDF report generation with Why This Score sections."""
    report = {
        "report_id": "test-rep-002",
        "tool_version": "1.0.0",
        "generated_at": "2026-09-29T23:30:00Z",
        "source_pcap_path": "capture.pcap",
        "source_pcap_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hosts": [
            {
                "host": "mail.corp.local",
                "posture_score": 75,
                "posture_grade": "C",
                "finding_summary": {"critical": 1, "high": 1, "medium": 1, "low": 0},
                "sessions": [sample_session_with_findings],
            }
        ],
    }

    enriched = enrich_report_with_explainability(report)

    # 1. HTML generation
    html_out = to_html(enriched)
    assert "Why This Score?" in html_out
    assert "WHY?" in html_out
    assert "ML Anomaly Assessment" in html_out
    assert "TLS Protocol Version" in html_out

    # 2. PDF generation
    pdf_path = tmp_path / "test_explainable_report.pdf"
    success = to_pdf(enriched, pdf_path)
    assert success is True
    assert pdf_path.exists()
    assert pdf_path.stat().st_size > 1000


def test_score_to_intuitive_grade_all_thresholds():
    """Verify single intuitive posture grade thresholds (A+–F) with SSL Labs concept."""
    # 0 -> A+ (Excellent)
    g, l, d, b = score_to_intuitive_grade(0)
    assert g == "A+"
    assert l == "Excellent"
    assert b == "0"

    # 5 -> A (Strong)
    g, l, d, b = score_to_intuitive_grade(5)
    assert g == "A"
    assert l == "Strong"
    assert b == "1-5"

    # 15 -> B (Good)
    g, l, d, b = score_to_intuitive_grade(15)
    assert g == "B"
    assert l == "Good"
    assert b == "6-15"

    # 30 -> C (Moderate)
    g, l, d, b = score_to_intuitive_grade(30)
    assert g == "C"
    assert l == "Moderate"
    assert b == "16-30"

    # 50 -> D (Weak)
    g, l, d, b = score_to_intuitive_grade(50)
    assert g == "D"
    assert l == "Weak"
    assert b == "31-50"

    # 75 -> E (Poor)
    g, l, d, b = score_to_intuitive_grade(75)
    assert g == "E"
    assert l == "Poor"
    assert b == "51-75"

    # 85 -> F (Critical)
    g, l, d, b = score_to_intuitive_grade(85)
    assert g == "F"
    assert l == "Critical"
    assert b == "76+"


def test_why_this_grade_breakdown_reasoning(sample_session_with_findings):
    """Test 'Why this grade?' breakdown linking findings, score penalties, evidence and ladder."""
    from securemailscope.rules.engine import Finding
    findings = [
        Finding(
            id="deprecated-tls-10",
            finding_id="f-1",
            session_id="s-1",
            host="mail.corp.com",
            category="deprecated-protocol",
            severity="critical",
            description="TLS 1.0 is negotiated",
            evidence_ref={"packet_number": 14, "byte_offset": 0},
        ),
        Finding(
            id="weak-cipher",
            finding_id="f-2",
            session_id="s-1",
            host="mail.corp.com",
            category="weak-cipher",
            severity="high",
            description="Weak RC4 cipher",
            evidence_ref={"packet_number": 14, "byte_offset": 32},
        ),
    ]

    grade_result = compute_host_grade("mail.corp.com", findings)

    # 40 (critical) + 25 (high) = 65 -> Grade E (Poor) (Bracket 51-75)
    assert grade_result.score == 65
    assert grade_result.grade == "E"
    assert grade_result.label == "Poor"

    why_grade = grade_result.why_this_grade
    assert why_grade is not None
    assert why_grade["grade"] == "E"
    assert why_grade["label"] == "Poor"
    assert "65/100" in why_grade["summary"]
    assert "51-75" in why_grade["summary"]

    # Verify determining factors link evidence & impact
    factors = why_grade["determining_factors"]
    assert len(factors) == 2
    f1 = factors[0]
    assert f1["rule_id"] == "deprecated-tls-10"
    assert f1["score_contribution"] == 40
    assert "Packet #14" in f1["evidence_ref"]
    assert "+40 points penalty" in f1["impact_on_grade"]

    # Visual grade ladder
    ladder = why_grade["grade_ladder"]
    assert len(ladder) == 7
    active_tier = [t for t in ladder if t["active"]]
    assert len(active_tier) == 1
    assert active_tier[0]["grade"] == "E"

    # Actionable remediation target to next grade tier
    next_target = why_grade["next_grade_target"]
    assert next_target is not None
    assert next_target["target_grade"] == "D"
    assert next_target["points_to_reduce"] == 15  # 65 - 50 = 15
    assert "deprecated-tls-10" in next_target["top_remediation_action"]


def test_custom_configurable_grade_thresholds():
    """Verify custom posture grading config can override thresholds and labels."""
    custom_cfg = PostureGradeConfig(
        thresholds=[
            PostureGradeThreshold(max_score=0, grade="A+", label="Flawless", description="No flaws"),
            PostureGradeThreshold(max_score=10, grade="A", label="Robust", description="Very robust"),
            PostureGradeThreshold(max_score=75, grade="D", label="Substandard", description="Substandard"),
        ],
        fallback=("F", "Disastrous", "Severe risks"),
    )

    # Score 72 with custom config should be Grade D (Substandard)
    g, l, d, b = score_to_intuitive_grade(72, config=custom_cfg)
    assert g == "D"
    assert l == "Substandard"
    assert b == "11-75"

    # Score 80 should hit fallback F (Disastrous)
    g, l, d, b = score_to_intuitive_grade(80, config=custom_cfg)
    assert g == "F"
    assert l == "Disastrous"

