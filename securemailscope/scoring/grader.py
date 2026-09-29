"""
securemailscope/scoring/grader.py
-----------------------------------
Per-host posture grading (A–F) with trend tracking.

Scoring formula
---------------
score = sum(severity_weight × finding_count_for_severity)

Weights (starter, tune in config):
  Critical = 40, High = 25, Medium = 10, Low = 3

Grade thresholds (starter):
  A: 0–5
  B: 6–15
  C: 16–30
  D: 31–50
  F: 51+

If SQLite has a prior scan for the same host, the grade delta is computed
and stored (e.g. "B → D since last scan 2024-01-15").
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from securemailscope.rules.engine import Finding

logger = logging.getLogger(__name__)

# Severity weights
SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 40,
    "high": 25,
    "medium": 10,
    "low": 3,
    "informational": 0,
}

# Standard intuitive grade labels matching SSL Labs
GRADE_LABELS: dict[str, str] = {
    "A+": "Excellent",
    "A": "Strong",
    "B": "Good",
    "C": "Moderate",
    "D": "Weak",
    "E": "Poor",
    "F": "Critical",
}

# Starter legacy thresholds for backwards compatibility
GRADE_THRESHOLDS: list[tuple[int, str]] = [
    (5,  "A"),
    (15, "B"),
    (30, "C"),
    (50, "D"),
]
GRADE_F = "F"


@dataclass
class PostureGradeThreshold:
    max_score: int
    grade: str
    label: str
    description: str


@dataclass
class PostureGradeConfig:
    """Configurable thresholds and descriptive labels for single intuitive posture grading."""

    thresholds: list[PostureGradeThreshold] = field(
        default_factory=lambda: [
            PostureGradeThreshold(
                max_score=0,
                grade="A+",
                label="Excellent",
                description="Pristine security posture with modern encryption and zero vulnerabilities",
            ),
            PostureGradeThreshold(
                max_score=5,
                grade="A",
                label="Strong",
                description="Strong encryption posture meeting modern compliance standards",
            ),
            PostureGradeThreshold(
                max_score=15,
                grade="B",
                label="Good",
                description="Good encryption security with minor configuration improvements recommended",
            ),
            PostureGradeThreshold(
                max_score=30,
                grade="C",
                label="Moderate",
                description="Moderate security posture with non-critical vulnerabilities or legacy settings",
            ),
            PostureGradeThreshold(
                max_score=50,
                grade="D",
                label="Weak",
                description="Weak security posture with deprecated ciphers, lack of PFS, or downgrade exposure",
            ),
            PostureGradeThreshold(
                max_score=75,
                grade="E",
                label="Poor",
                description="Poor security posture with obsolete TLS protocols or multiple high-severity findings",
            ),
        ]
    )
    fallback: tuple[str, str, str] = (
        "F",
        "Critical",
        "Critical security posture with active vulnerabilities or plaintext transmission risks",
    )


@dataclass
class PostureGrade:
    host: str
    score: int
    grade: str
    finding_counts: dict[str, int] = field(default_factory=dict)
    grade_delta: Optional[str] = None   # e.g. "B → D since last scan"
    previous_grade: Optional[str] = None
    previous_scan_date: Optional[str] = None
    label: str = "Strong"
    description: str = ""
    why_this_grade: Optional[dict] = None


def score_to_intuitive_grade(
    score: int,
    config: Optional[PostureGradeConfig] = None,
) -> tuple[str, str, str, str]:
    """
    Map a risk score to (grade, label, description, bracket_string).
    """
    cfg = config or PostureGradeConfig()
    prev_max = 0
    for i, t in enumerate(cfg.thresholds):
        if score <= t.max_score:
            if i == 0:
                bracket = "0"
            else:
                bracket = f"{prev_max + 1}-{t.max_score}"
            return t.grade, t.label, t.description, bracket
        prev_max = t.max_score

    f_grade, f_label, f_desc = cfg.fallback
    bracket = f"{prev_max + 1}+"
    return f_grade, f_label, f_desc, bracket


def generate_why_this_grade(
    host: str,
    score: int,
    grade: str,
    label: str,
    bracket: str,
    findings: list[Finding],
    counts: dict[str, int],
    config: Optional[PostureGradeConfig] = None,
) -> dict:
    """
    Generate transparent, deterministic 'Why this grade?' reasoning for an analyst or judge.
    """
    cfg = config or PostureGradeConfig()

    determining_factors = []
    for f in findings:
        sev = f.severity.lower()
        w = SEVERITY_WEIGHTS.get(sev, 10)
        ev_pkt = f.evidence_ref.get("packet_number", 0) if hasattr(f, "evidence_ref") and f.evidence_ref else 0
        ev_off = f.evidence_ref.get("byte_offset", 0) if hasattr(f, "evidence_ref") and f.evidence_ref else 0
        determining_factors.append({
            "finding_id": getattr(f, "finding_id", f.id),
            "rule_id": f.id,
            "feature": f.category.replace("-", " ").title() if hasattr(f, "category") else "Security Policy",
            "severity": sev,
            "description": f.description,
            "score_contribution": w,
            "observed_value": getattr(f, "observed_value", f.description),
            "evidence_ref": f"Packet #{ev_pkt} (Offset {ev_off})",
            "impact_on_grade": f"+{w} points penalty towards Grade {grade}",
        })

    crit = counts.get("critical", 0)
    high = counts.get("high", 0)
    med = counts.get("medium", 0)
    low = counts.get("low", 0)

    if not findings:
        summary = (
            f"Host '{host}' achieved Posture Grade {grade} ({label}) with a perfect score of 0/100. "
            "Zero security findings or cryptographic policy violations were detected across all analyzed sessions."
        )
    else:
        issue_parts = []
        if crit:
            issue_parts.append(f"{crit} Critical")
        if high:
            issue_parts.append(f"{high} High")
        if med:
            issue_parts.append(f"{med} Medium")
        if low:
            issue_parts.append(f"{low} Low")
        issues_str = ", ".join(issue_parts)

        summary = (
            f"Host '{host}' received Posture Grade {grade} ({label}) with a cumulative risk score of {score}/100 "
            f"(Bracket: {bracket}). This grade was determined by {len(findings)} adverse findings ({issues_str})."
        )

    # Visual grade ladder
    ladder = []
    prev_m = 0
    for i, t in enumerate(cfg.thresholds):
        rng = "0" if i == 0 else f"{prev_m + 1}-{t.max_score}"
        ladder.append({
            "grade": t.grade,
            "label": t.label,
            "range": rng,
            "active": (t.grade == grade),
        })
        prev_m = t.max_score
    ladder.append({
        "grade": cfg.fallback[0],
        "label": cfg.fallback[1],
        "range": f"{prev_m + 1}+",
        "active": (cfg.fallback[0] == grade),
    })

    # Next grade target
    next_target = None
    all_tiers = [(t.max_score, t.grade, t.label) for t in cfg.thresholds]
    for max_s, g, l in reversed(all_tiers):
        if score > max_s:
            points_to_drop = score - max_s
            top_rec = ""
            if determining_factors:
                top_f = max(determining_factors, key=lambda x: x["score_contribution"])
                top_rec = f"Remediate highest penalty finding '{top_f['rule_id']}' (-{top_f['score_contribution']} pts) to advance towards Grade {g}."
            next_target = {
                "target_grade": g,
                "target_label": l,
                "points_to_reduce": points_to_drop,
                "top_remediation_action": top_rec or f"Reduce score by {points_to_drop} points to reach Grade {g} ({l}).",
            }
            break

    return {
        "grade": grade,
        "label": label,
        "score": score,
        "threshold_bracket": bracket,
        "headline": f"Security Posture: {grade} — {label}",
        "summary": summary,
        "determining_factors": determining_factors,
        "grade_ladder": ladder,
        "next_grade_target": next_target,
    }


def compute_host_grade(
    host: str,
    findings: list[Finding],
    previous_grade: Optional[str] = None,
    previous_scan_date: Optional[str] = None,
    config: Optional[PostureGradeConfig] = None,
) -> PostureGrade:
    """
    Compute the posture grade for a single host.

    Parameters
    ----------
    host : str
    findings : list[Finding]
        All findings for this host (across all sessions).
    previous_grade : str | None
        Grade from the most recent SQLite scan record.
    previous_scan_date : str | None
        ISO 8601 date of the previous scan.
    config : PostureGradeConfig | None
        Custom configurable grade thresholds and labels.
    """
    counts: dict[str, int] = {sev: 0 for sev in SEVERITY_WEIGHTS}
    for f in findings:
        sev = f.severity.lower()
        counts[sev] = counts.get(sev, 0) + 1

    score = sum(
        SEVERITY_WEIGHTS.get(sev, 0) * count
        for sev, count in counts.items()
    )

    grade, label, desc, bracket = score_to_intuitive_grade(score, config)
    why_this_grade = generate_why_this_grade(host, score, grade, label, bracket, findings, counts, config)

    delta: Optional[str] = None
    if previous_grade and previous_grade != grade:
        delta = f"{previous_grade} → {grade} since last scan {previous_scan_date or ''}"
    elif previous_grade == grade:
        delta = f"No change from {grade} (last scan {previous_scan_date or ''})"

    return PostureGrade(
        host=host,
        score=score,
        grade=grade,
        finding_counts=counts,
        grade_delta=delta,
        previous_grade=previous_grade,
        previous_scan_date=previous_scan_date,
        label=label,
        description=desc,
        why_this_grade=why_this_grade,
    )


def _score_to_grade(score: int, thresholds: Optional[list[tuple[int, str]]] = None) -> str:
    """Legacy helper: returns letter grade according to thresholds."""
    thresh = thresholds or GRADE_THRESHOLDS
    for threshold, grade in thresh:
        if score <= threshold:
            return grade
    return GRADE_F
