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

# Grade thresholds
GRADE_THRESHOLDS: list[tuple[int, str]] = [
    (5,  "A"),
    (15, "B"),
    (30, "C"),
    (50, "D"),
]
GRADE_F = "F"


@dataclass
class PostureGrade:
    host: str
    score: int
    grade: str
    finding_counts: dict[str, int] = field(default_factory=dict)
    grade_delta: Optional[str] = None   # e.g. "B → D since last scan"
    previous_grade: Optional[str] = None
    previous_scan_date: Optional[str] = None


def compute_host_grade(
    host: str,
    findings: list[Finding],
    previous_grade: Optional[str] = None,
    previous_scan_date: Optional[str] = None,
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
    """
    counts: dict[str, int] = {sev: 0 for sev in SEVERITY_WEIGHTS}
    for f in findings:
        sev = f.severity.lower()
        counts[sev] = counts.get(sev, 0) + 1

    score = sum(
        SEVERITY_WEIGHTS.get(sev, 0) * count
        for sev, count in counts.items()
    )

    grade = _score_to_grade(score)
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
    )


def _score_to_grade(score: int) -> str:
    for threshold, grade in GRADE_THRESHOLDS:
        if score <= threshold:
            return grade
    return GRADE_F
