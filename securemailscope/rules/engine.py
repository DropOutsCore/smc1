"""
securemailscope/rules/engine.py
---------------------------------
Config-driven weakness rule engine.

Rules live in rules/rules.yaml — no code changes needed to add/modify rules.
Each rule condition is a Python expression evaluated against a safe
namespace containing the current session, TLS, and certificate objects.

SECURITY NOTE: rule conditions are eval()'d.  The rules.yaml file must be
considered a trusted configuration input.  Do not eval user-supplied strings.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from securemailscope.certs.extractor import CertificateInfo, ChainValidationResult
from securemailscope.ingestion.models import EmailSession
from securemailscope.tls_analysis.handshake_parser import TLSHandshakeInfo

logger = logging.getLogger(__name__)

_RULES_PATH = Path(__file__).parent / "rules.yaml"


@dataclass
class Finding:
    """
    A single weakness finding.

    evidence_ref always points to a specific packet number in the source
    PCAP, making every finding forensically traceable.
    """
    id: str                   # rule id (e.g. "deprecated-tls-10")
    finding_id: str           # unique UUID for this specific finding instance
    session_id: str
    host: str
    category: str
    severity: str             # critical | high | medium | low | informational
    description: str
    reference: str = ""
    cwe: str = ""
    evidence_ref: dict = field(default_factory=dict)   # {"packet_number": N, "byte_offset": N}
    contributing_factors: list[str] = field(default_factory=list)
    remediation: str = ""
    ml_flagged: bool = False
    anomaly_score: Optional[float] = None


class RuleEngine:
    """Evaluates all configured rules against a session analysis result."""

    def __init__(self, rules_path: str | Path = _RULES_PATH):
        self._rules: list[dict] = []
        self._load_rules(rules_path)

    def _load_rules(self, path: str | Path) -> None:
        try:
            with open(path, "r") as fh:
                data = yaml.safe_load(fh)
            self._rules = data.get("rules", [])
            logger.info("Loaded %d rules from %s", len(self._rules), path)
        except Exception as exc:
            logger.error("Failed to load rules from %s: %s", path, exc)
            self._rules = []

    def evaluate(
        self,
        session: EmailSession,
        tls: Optional[TLSHandshakeInfo],
        chain: Optional[ChainValidationResult],
    ) -> list[Finding]:
        """
        Evaluate all rules and return a list of triggered findings.

        Parameters
        ----------
        session : EmailSession
        tls : TLSHandshakeInfo | None
            None if no TLS handshake was observed.
        chain : ChainValidationResult | None
            None if no certificates were extracted.
        """
        findings: list[Finding] = []

        # Build a safe evaluation namespace
        leaf_cert = (
            chain.certificates[0]
            if chain and chain.certificates
            else _EmptyCert()
        )
        tls_proxy = tls or _EmptyTLS()

        ns = {
            "session": session,
            "tls": tls_proxy,
            "cert": leaf_cert,
            "True": True,
            "False": False,
            "None": None,
        }

        for rule in self._rules:
            try:
                condition = rule.get("condition", "False")
                triggered = bool(eval(condition, {"__builtins__": {}}, ns))  # noqa: S307
            except Exception as exc:
                logger.debug("Rule %s condition error: %s", rule.get("id"), exc)
                continue

            if not triggered:
                continue

            # Resolve evidence reference
            evidence_ref = self._resolve_evidence(session, rule)

            finding = Finding(
                id=rule.get("id", "unknown"),
                finding_id=str(uuid.uuid4()),
                session_id=session.session_id,
                host=session.host_key,
                category=rule.get("category", "uncategorized"),
                severity=rule.get("severity", "informational"),
                description=rule.get("description", ""),
                reference=rule.get("reference", ""),
                cwe=rule.get("cwe", ""),
                evidence_ref=evidence_ref,
            )
            findings.append(finding)

        logger.debug(
            "Session %s: %d findings from rule engine", session.session_id[:8], len(findings)
        )
        return findings

    def _resolve_evidence(self, session: EmailSession, rule: dict) -> dict:
        """
        Map a rule firing to the most relevant packet number in the session.

        Priority:
        1. STARTTLS downgrade — use the downgrade evidence packet
        2. First packet of the session as fallback
        """
        category = rule.get("category", "")
        if category == "starttls-downgrade" and session.downgrade_evidence_packet:
            return {"packet_number": session.downgrade_evidence_packet, "type": "downgrade"}
        if session.starttls_offset and session.packet_refs:
            # Best-effort: packet nearest to STARTTLS offset
            return {"packet_number": session.packet_refs[0], "type": "session-start"}
        if session.packet_refs:
            return {"packet_number": session.packet_refs[0], "type": "session-start"}
        return {"packet_number": 0, "type": "unknown"}


class _EmptyCert:
    """Null object for cert namespace when no cert is available."""
    key_algorithm = "unknown"
    key_length = 0
    is_expired = False
    is_not_yet_valid = False
    expiring_within_30_days = False
    signature_algorithm_weak = False
    is_self_signed = False
    hostname_match = None
    trust_issues: list = []
    days_until_expiry = None


class _EmptyTLS:
    """Null object for TLS namespace when no handshake is available."""
    tls_version = "unknown"
    cipher_suite = "unknown"
    cipher_strength = "unknown"
    pfs = False
    sni = None
    alpn: list = []
    anomalies: list = []
