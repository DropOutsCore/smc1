"""securemailscope/scoring/__init__.py"""

from securemailscope.scoring.grader import (
    PostureGrade,
    PostureGradeConfig,
    PostureGradeThreshold,
    compute_host_grade,
    score_to_intuitive_grade,
    generate_why_this_grade,
    GRADE_LABELS,
)
from securemailscope.scoring.explainability import (
    ScoringWeightConfig,
    explain_session_score,
    explain_host_score,
    enrich_report_with_explainability,
)

__all__ = [
    "PostureGrade",
    "PostureGradeConfig",
    "PostureGradeThreshold",
    "compute_host_grade",
    "score_to_intuitive_grade",
    "generate_why_this_grade",
    "GRADE_LABELS",
    "ScoringWeightConfig",
    "explain_session_score",
    "explain_host_score",
    "enrich_report_with_explainability",
]
