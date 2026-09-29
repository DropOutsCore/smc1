"""
Tests for scoring, forensics, and remediation modules.
"""

from __future__ import annotations

import pytest
from securemailscope.scoring.grader import compute_host_grade, _score_to_grade
from securemailscope.forensics.custody import hash_report, build_custody_metadata
from securemailscope.remediation.templates import get_remediation


# ─────────────────────────────────────────────────────────────────
# Grading
# ─────────────────────────────────────────────────────────────────

def test_grade_thresholds():
    """Grade thresholds behave as configured (PRD §4.6)."""
    assert _score_to_grade(0) == "A"
    assert _score_to_grade(5) == "A"
    assert _score_to_grade(6) == "B"
    assert _score_to_grade(15) == "B"
    assert _score_to_grade(16) == "C"
    assert _score_to_grade(30) == "C"
    assert _score_to_grade(31) == "D"
    assert _score_to_grade(50) == "D"
    assert _score_to_grade(51) == "F"
    assert _score_to_grade(999) == "F"


def test_host_grade_no_findings():
    """A host with no findings gets grade A."""
    grade = compute_host_grade("1.2.3.4:25", [])
    assert grade.grade == "A"
    assert grade.score == 0


def test_host_grade_critical():
    """One critical finding (weight=40) → score=40 → grade D."""
    from securemailscope.rules.engine import Finding
    import uuid
    f = Finding(
        id="test", finding_id=str(uuid.uuid4()), session_id="s1", host="1.2.3.4:25",
        category="test", severity="critical", description="test",
        evidence_ref={"packet_number": 1},
    )
    grade = compute_host_grade("1.2.3.4:25", [f])
    assert grade.grade == "D"   # 40 → D
    assert grade.score == 40


def test_grade_delta_computed(mock_session):
    """Grade delta is computed when previous scan exists."""
    from securemailscope.rules.engine import Finding
    import uuid
    findings = [
        Finding(
            id=f"f{i}", finding_id=str(uuid.uuid4()), session_id="s", host="1:25",
            category="c", severity="high", description="d",
            evidence_ref={"packet_number": 1},
        )
        for i in range(3)
    ]
    grade = compute_host_grade("1:25", findings, previous_grade="A", previous_scan_date="2024-01-01")
    assert grade.previous_grade == "A"
    assert grade.grade_delta is not None
    assert "A →" in grade.grade_delta or "No change" in grade.grade_delta


# ─────────────────────────────────────────────────────────────────
# Forensics / Hashing
# ─────────────────────────────────────────────────────────────────

def test_report_hash_reproducible():
    """SHA-256 hash of a report is deterministic."""
    content = '{"report_id": "test", "data": "value"}'
    h1 = hash_report(content)
    h2 = hash_report(content)
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex


def test_report_hash_changes_on_mutation():
    """SHA-256 changes when report content changes."""
    c1 = '{"report_id": "aaa"}'
    c2 = '{"report_id": "bbb"}'
    assert hash_report(c1) != hash_report(c2)


# ─────────────────────────────────────────────────────────────────
# Remediation
# ─────────────────────────────────────────────────────────────────

def test_remediation_postfix_deprecated_tls():
    """Postfix remediation template returned for deprecated-protocol + Postfix banner."""
    text = get_remediation("deprecated-protocol", "220 mail.example.com Postfix ESMTP")
    assert "postfix" in text.lower()
    assert "tls" in text.lower()


def test_remediation_dovecot():
    """Dovecot remediation template returned for Dovecot banner."""
    text = get_remediation("deprecated-protocol", "* OK Dovecot ready")
    assert "dovecot" in text.lower()


def test_remediation_fallback():
    """Unknown category returns a fallback string (not an exception)."""
    text = get_remediation("unknown-category", "")
    assert isinstance(text, str)
    assert len(text) > 0


def test_remediation_starttls_downgrade():
    """STARTTLS downgrade has a remediation template."""
    text = get_remediation("starttls-downgrade", "")
    assert "starttls" in text.lower() or "mta-sts" in text.lower()


# ─────────────────────────────────────────────────────────────────
# ML features
# ─────────────────────────────────────────────────────────────────

def test_feature_vector_shape(mock_session, mock_tls_info):
    """Feature vector has exactly NUM_FEATURES dimensions."""
    from securemailscope.ml.features import build_feature_vector, NUM_FEATURES
    fv = build_feature_vector(mock_session, mock_tls_info, None)
    assert fv.shape == (NUM_FEATURES,)


def test_feature_vector_downgrade_flag(mock_session, mock_tls_info):
    """downgrade_suspected feature (index 17) is 1.0 when downgrade detected."""
    from securemailscope.ml.features import build_feature_vector
    mock_session.downgrade_suspected = True
    fv = build_feature_vector(mock_session, mock_tls_info, None)
    assert fv[17] == 1.0


def test_feature_vector_pfs_flag(mock_tls_info, mock_session):
    """pfs_enabled feature is 0.0 for RSA key exchange."""
    from securemailscope.ml.features import build_feature_vector
    mock_tls_info.pfs = False
    fv = build_feature_vector(mock_session, mock_tls_info, None)
    assert fv[5] == 0.0  # pfs_enabled
