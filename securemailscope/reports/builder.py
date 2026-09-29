"""
securemailscope/reports/builder.py
-------------------------------------
Report data assembly — builds the canonical JSON report structure.

This is the single source of truth for all other export formats (HTML, PDF)
and the dashboard.  The schema is locked per PRD §4.9 and must not drift.

JSON Schema (v1):
{
  "report_id": "string",
  "source_pcap_sha256": "string",
  "source_pcap_path": "string",
  "generated_at": "iso8601",
  "tool_version": "string",
  "tls13_visibility_note": "string",
  "custody": { ... },
  "hosts": [
    {
      "host": "string",
      "posture_grade": "A|B|C|D|F",
      "posture_score": int,
      "grade_delta": "string|null",
      "finding_summary": { "critical": int, "high": int, "medium": int, "low": int },
      "sessions": [
        {
          "session_id": "string",
          "protocol": "SMTP|IMAP|POP3",
          "src_ip": "string",
          "dst_ip": "string",
          "src_port": int,
          "dst_port": int,
          "starttls_detected": bool,
          "downgrade_suspected": bool,
          "tls_version": "string",
          "cipher_suite": "string",
          "cipher_strength": "string",
          "pfs": bool,
          "key_exchange": "string",
          "sni": "string|null",
          "tls13_visibility_limited": bool,
          "certificate": {
            "subject": "string",
            "issuer": "string",
            "key_algorithm": "string",
            "key_length": int,
            "key_strength": "string",
            "signature_algorithm": "string",
            "expires": "iso8601",
            "days_until_expiry": int,
            "is_expired": bool,
            "is_self_signed": bool,
            "hostname_match": bool|null,
            "sans": ["string"]
          } | null,
          "ml_risk_label": "string",
          "ml_confidence": float,
          "anomaly_detected": bool,
          "anomaly_score": float,
          "findings": [
            {
              "id": "string",
              "finding_id": "string",
              "category": "string",
              "severity": "critical|high|medium|low",
              "description": "string",
              "reference": "string",
              "cwe": "string",
              "contributing_factors": ["string"],
              "evidence_ref": {"packet_number": int},
              "remediation": "string",
              "ml_flagged": bool
            }
          ]
        }
      ]
    }
  ]
}
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional

from securemailscope.certs.extractor import CertificateInfo, ChainValidationResult
from securemailscope.forensics.custody import CustodyMetadata, hash_report
from securemailscope.ingestion.models import EmailSession
from securemailscope.rules.engine import Finding
from securemailscope.scoring.grader import PostureGrade
from securemailscope.tls_analysis.handshake_parser import TLSHandshakeInfo

logger = logging.getLogger(__name__)

_TLS13_VISIBILITY_NOTE = (
    "TLS 1.3 encrypts most handshake fields after ServerHello. "
    "Certificate details and some handshake parameters may not be visible "
    "in passive captures. Affected sessions are flagged with "
    "'tls13_visibility_limited: true'."
)


@dataclass
class SessionAnalysisResult:
    """All analysis results for one email session."""
    session: EmailSession
    tls: Optional[TLSHandshakeInfo] = None
    chain: Optional[ChainValidationResult] = None
    findings: list[Finding] = field(default_factory=list)
    ml_risk_label: str = "unknown"
    ml_confidence: float = 0.0
    anomaly_detected: bool = False
    anomaly_score: float = 0.0


def build_report(
    custody: CustodyMetadata,
    session_results: list[SessionAnalysisResult],
    host_grades: dict[str, PostureGrade],
) -> dict:
    """
    Assemble the canonical JSON report dictionary.

    Parameters
    ----------
    custody : CustodyMetadata
    session_results : list[SessionAnalysisResult]
    host_grades : dict[str, PostureGrade]
        Keyed by host_key ("ip:port").

    Returns
    -------
    dict
        Report dict that can be serialised to JSON.
    """
    # Group sessions by host
    host_sessions: dict[str, list[SessionAnalysisResult]] = defaultdict(list)
    for sr in session_results:
        host_sessions[sr.session.host_key].append(sr)

    hosts_output: list[dict] = []
    for host, results in host_sessions.items():
        grade_obj = host_grades.get(host)
        grade = grade_obj.grade if grade_obj else "F"
        score = grade_obj.score if grade_obj else 0
        grade_delta = grade_obj.grade_delta if grade_obj else None
        finding_counts = grade_obj.finding_counts if grade_obj else {}
        grade_label = getattr(grade_obj, "label", "Critical") if grade_obj else "Critical"
        why_this_grade = getattr(grade_obj, "why_this_grade", None) if grade_obj else None

        sessions_output = [_build_session_dict(sr) for sr in results]

        hosts_output.append({
            "host": host,
            "posture_grade": grade,
            "posture_label": grade_label,
            "posture_score": score,
            "grade_delta": grade_delta,
            "finding_summary": finding_counts,
            "why_this_grade": why_this_grade,
            "sessions": sessions_output,
        })

    # Sort hosts by grade (worst first)
    grade_order = {"F": 0, "E": 1, "D": 2, "C": 3, "B": 4, "A": 5, "A+": 6}
    hosts_output.sort(key=lambda h: grade_order.get(h["posture_grade"], 7))

    report = {
        "report_id": custody.report_id,
        "source_pcap_sha256": custody.source_pcap_sha256,
        "source_pcap_path": custody.source_pcap_path,
        "source_pcap_size_bytes": custody.source_pcap_size_bytes,
        "generated_at": custody.generated_at,
        "tool_version": custody.tool_version,
        "analyst_host": custody.analyst_host,
        "tls13_visibility_note": _TLS13_VISIBILITY_NOTE,
        "custody": custody.to_dict(),
        "hosts": hosts_output,
    }
    return report


def _build_session_dict(sr: SessionAnalysisResult) -> dict:
    """Convert one SessionAnalysisResult to its JSON representation."""
    s = sr.session
    tls = sr.tls
    chain = sr.chain

    # Certificate
    cert_dict = None
    if chain and chain.certificates:
        leaf = chain.certificates[0]
        cert_dict = {
            "subject": leaf.subject,
            "issuer": leaf.issuer,
            "serial_number": leaf.serial_number,
            "key_algorithm": leaf.key_algorithm,
            "key_length": leaf.key_length,
            "key_strength": leaf.key_strength,
            "signature_algorithm": leaf.signature_algorithm,
            "expires": leaf.not_after.isoformat() if leaf.not_after else None,
            "not_before": leaf.not_before.isoformat() if leaf.not_before else None,
            "days_until_expiry": leaf.days_until_expiry,
            "is_expired": leaf.is_expired,
            "is_not_yet_valid": leaf.is_not_yet_valid,
            "expiring_within_30_days": leaf.expiring_within_30_days,
            "is_self_signed": leaf.is_self_signed,
            "hostname_match": leaf.hostname_match,
            "sans": leaf.sans,
            "chain_length": chain.chain_length,
            "chain_valid": chain.valid,
            "chain_issues": chain.issues,
        }

    # Findings
    findings_list = [
        {
            "id": f.id,
            "finding_id": f.finding_id,
            "category": f.category,
            "severity": f.severity,
            "description": f.description,
            "reference": f.reference,
            "cwe": f.cwe,
            "contributing_factors": f.contributing_factors,
            "evidence_ref": f.evidence_ref,
            "remediation": f.remediation,
            "ml_flagged": f.ml_flagged,
            "anomaly_score": f.anomaly_score,
        }
        for f in sr.findings
    ]

    return {
        "session_id": s.session_id,
        "protocol": s.protocol,
        "src_ip": s.src_ip,
        "dst_ip": s.dst_ip,
        "src_port": s.src_port,
        "dst_port": s.dst_port,
        "banner": s.banner,
        "starttls_detected": s.starttls_detected,
        "downgrade_suspected": s.downgrade_suspected,
        "is_implicit_tls": s.is_implicit_tls,
        "tls_version": tls.tls_version if tls else "none",
        "cipher_suite": tls.cipher_suite if tls else "none",
        "cipher_strength": tls.cipher_strength if tls else "unknown",
        "pfs": tls.pfs if tls else False,
        "key_exchange": tls.key_exchange if tls else "none",
        "sni": tls.sni if tls else None,
        "alpn": tls.alpn if tls else [],
        "tls_anomalies": tls.anomalies if tls else [],
        "tls13_visibility_limited": tls.tls13_visibility_limited if tls else False,
        "certificate": cert_dict,
        "ml_risk_label": sr.ml_risk_label,
        "ml_confidence": round(sr.ml_confidence, 4),
        "anomaly_detected": sr.anomaly_detected,
        "anomaly_score": round(sr.anomaly_score, 4),
        "packet_refs": s.packet_refs[:10],   # first 10 for brevity
        "findings": findings_list,
    }


def to_json(report: dict, indent: int = 2) -> str:
    """Serialise report dict to JSON string."""
    return json.dumps(report, indent=indent, default=str)
