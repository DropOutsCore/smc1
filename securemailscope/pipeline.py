"""
securemailscope/pipeline.py
------------------------------
Main analysis pipeline — orchestrates all modules end-to-end.

Usage (from main.py CLI):
  pipeline.run(pcap_path, output_dir, config)

The pipeline NEVER:
  • Opens the source PCAP for writing
  • Connects to the internet (enrichment is opt-in and off by default)
  • Decrypts application-layer email content
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np

from securemailscope.certs.extractor import extract_certificates
from securemailscope.forensics.custody import build_custody_metadata, hash_report
from securemailscope.ingestion.loader import load_pcap
from securemailscope.ingestion.protocol_detector import build_email_sessions
from securemailscope.ingestion.reassembler import reconstruct_tcp_streams
from securemailscope.ml.classifier import AnomalyDetector, RiskClassifier
from securemailscope.ml.features import build_feature_vector
from securemailscope.remediation.templates import get_remediation
from securemailscope.reports.builder import (
    SessionAnalysisResult,
    build_report,
    to_json,
)
from securemailscope.reports.exporter import to_html, to_pdf
from securemailscope.rules.engine import Finding, RuleEngine
from securemailscope.scoring.grader import compute_host_grade
from securemailscope.storage.database import ScanDatabase
from securemailscope.tls_analysis.handshake_parser import parse_handshake

logger = logging.getLogger(__name__)


@dataclass
class PipelineConfig:
    """Runtime configuration for an analysis run."""
    output_dir: str = "."
    rules_path: Optional[str] = None
    db_path: Optional[str] = None
    enable_enrichment: bool = False          # off by default
    enable_ml: bool = True
    enable_anomaly: bool = True
    generate_html: bool = True
    generate_pdf: bool = True
    verbose: bool = False


@dataclass
class PipelineResult:
    """Outcome of a complete analysis run."""
    report: dict = field(default_factory=dict)
    json_path: Optional[str] = None
    html_path: Optional[str] = None
    pdf_path: Optional[str] = None
    session_count: int = 0
    finding_count: int = 0
    error: Optional[str] = None


def _handle_json_report(json_path: Path, config: PipelineConfig) -> PipelineResult:
    """Load, validate, and process an existing JSON report."""
    result = PipelineResult()
    output_dir = Path(config.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Loading existing JSON report — %s", json_path)
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            report = json.load(f)
    except Exception as exc:
        result.error = f"Failed to load JSON report: {exc}"
        logger.error(result.error)
        return result

    from securemailscope.forensics.evidence_layer import enrich_report_with_forensics
    from securemailscope.scoring.explainability import enrich_report_with_explainability
    report = enrich_report_with_forensics(report)
    report = enrich_report_with_explainability(report)
    result.report = report
    result.json_path = str(json_path)

    all_sessions = []
    finding_count = 0
    for host in report.get("hosts", []):
        for s in host.get("sessions", []):
            all_sessions.append(s)
            finding_count += len(s.get("findings", []))
    result.session_count = len(all_sessions)
    result.finding_count = finding_count

    base_name = json_path.stem
    if base_name.endswith("_report"):
        base_name = base_name[:-7]

    if config.generate_html:
        try:
            html_str = to_html(report)
            html_path = output_dir / f"{base_name}_report.html"
            html_path.write_text(html_str, encoding="utf-8")
            result.html_path = str(html_path)
            logger.info("HTML report: %s", html_path)
        except Exception as exc:
            logger.warning("Could not generate HTML report from JSON: %s", exc)

    if config.generate_pdf:
        try:
            pdf_path = output_dir / f"{base_name}_report.pdf"
            success = to_pdf(report, pdf_path)
            if success:
                result.pdf_path = str(pdf_path)
        except Exception as exc:
            logger.warning("Could not generate PDF report from JSON: %s", exc)

    logger.info(
        "JSON report loaded: %d hosts, %d sessions, %d findings",
        len(report.get("hosts", [])), result.session_count, result.finding_count,
    )
    return result


def run(pcap_path: str, config: PipelineConfig) -> PipelineResult:
    """
    Execute the analysis pipeline on a PCAP file, or load an existing JSON report.

    Parameters
    ----------
    pcap_path : str
        Path to the .pcap, .pcapng, or .json file.
    config : PipelineConfig

    Returns
    -------
    PipelineResult
    """
    result = PipelineResult()
    input_path = Path(pcap_path)

    if not input_path.is_file():
        result.error = f"File not found: {pcap_path}"
        logger.error(result.error)
        return result

    # Transparently handle existing JSON reports
    if input_path.suffix.lower() == ".json":
        return _handle_json_report(input_path, config)

    output_dir = Path(config.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Phase 1: Load & ingest ────────────────────────────────────────────
    logger.info("Phase 1: Loading PCAP — %s", pcap_path)
    try:
        meta, segments = load_pcap(pcap_path)
    except Exception as exc:
        result.error = f"Failed to load PCAP: {exc}"
        logger.error(result.error)
        return result

    custody = build_custody_metadata(pcap_path, meta.sha256, meta.file_size_bytes)

    # ── Phase 2: TCP reassembly & session reconstruction ─────────────────
    logger.info("Phase 2: TCP reassembly — %d segments", len(segments))
    streams = reconstruct_tcp_streams(segments)
    sessions = build_email_sessions(streams)
    result.session_count = len(sessions)
    logger.info("Identified %d email sessions", len(sessions))

    if not sessions:
        logger.warning("No email sessions found in PCAP.")

    # ── Phase 3: TLS handshake & certificate analysis ─────────────────────
    logger.info("Phase 3: TLS handshake & certificate analysis")
    session_results: list[SessionAnalysisResult] = []
    for session in sessions:
        sr = SessionAnalysisResult(session=session)

        # Determine TLS start offset
        start_offset = 0
        if session.starttls_offset is not None:
            start_offset = session.starttls_offset
        elif session.is_implicit_tls:
            start_offset = 0

        # Only parse TLS if we have a TLS section
        if session.starttls_detected or session.is_implicit_tls:
            try:
                stream_data = session.stream.combined_data
                handshake_pkt = (
                    session.packet_refs[0] if session.packet_refs else 0
                )
                sr.tls = parse_handshake(
                    stream_data,
                    start_offset=start_offset,
                    handshake_start_packet=handshake_pkt,
                    client_data=session.stream.client_data,
                    server_data=session.stream.server_data,
                )

                # Certificate extraction
                if sr.tls.certificate_chain_der:
                    sr.chain = extract_certificates(
                        sr.tls.certificate_chain_der, sr.tls.sni
                    )
            except Exception as exc:
                logger.warning(
                    "TLS/cert analysis failed for session %s: %s",
                    session.session_id[:8], exc,
                )

        session_results.append(sr)

    # ── Phase 4: Rule engine ──────────────────────────────────────────────
    logger.info("Phase 4: Rule engine evaluation")
    rules_kwargs = {}
    if config.rules_path:
        rules_kwargs["rules_path"] = config.rules_path
    rule_engine = RuleEngine(**rules_kwargs)

    for sr in session_results:
        findings = rule_engine.evaluate(sr.session, sr.tls, sr.chain)

        # Attach remediation to each finding
        for f in findings:
            f.remediation = get_remediation(f.category, sr.session.banner)

        sr.findings = findings
        result.finding_count += len(findings)

    # ── Phase 5: ML risk classification & anomaly detection ──────────────
    if config.enable_ml and session_results:
        logger.info("Phase 5: ML risk scoring")
        _run_ml(session_results, config)

    # ── Phase 6: Posture scoring ──────────────────────────────────────────
    logger.info("Phase 6: Posture scoring")
    db_kwargs = {}
    if config.db_path:
        db_kwargs["db_path"] = config.db_path
    db = ScanDatabase(**db_kwargs)

    # Group findings by host
    from collections import defaultdict
    host_findings: dict[str, list[Finding]] = defaultdict(list)
    for sr in session_results:
        for f in sr.findings:
            host_findings[sr.session.host_key].append(f)

    host_grades = {}
    for host, findings in host_findings.items():
        prev = db.get_previous_grade(host)
        prev_grade, prev_date = prev if prev else (None, None)
        grade = compute_host_grade(host, findings, prev_grade, prev_date)
        host_grades[host] = grade

    # Also grade hosts with no findings (they're fine = A)
    for sr in session_results:
        hk = sr.session.host_key
        if hk not in host_grades:
            host_grades[hk] = compute_host_grade(hk, [])

    # ── Phase 7: Build & export reports ──────────────────────────────────
    logger.info("Phase 7: Report generation")
    report = build_report(custody, session_results, host_grades)

    # Non-invasive forensic evidence layer enrichment
    from securemailscope.forensics.evidence_layer import enrich_report_with_forensics
    report = enrich_report_with_forensics(report, pcap_path=pcap_path, pcap_sha256=meta.sha256)

    # Non-invasive explainable AI / risk assessment layer enrichment
    from securemailscope.scoring.explainability import enrich_report_with_explainability
    report = enrich_report_with_explainability(report)

    json_str = to_json(report)

    # Compute report hash (chain-of-custody)
    from securemailscope.forensics.custody import hash_report as _hash
    report["custody"]["report_sha256"] = _hash(json_str)
    # Re-serialise with hash
    json_str = to_json(report)

    base_name = Path(pcap_path).stem
    json_path = output_dir / f"{base_name}_report.json"
    json_path.write_text(json_str, encoding="utf-8")
    result.json_path = str(json_path)
    logger.info("JSON report: %s", json_path)

    if config.generate_html:
        html_str = to_html(report)
        html_path = output_dir / f"{base_name}_report.html"
        html_path.write_text(html_str, encoding="utf-8")
        result.html_path = str(html_path)
        logger.info("HTML report: %s", html_path)

    if config.generate_pdf:
        pdf_path = output_dir / f"{base_name}_report.pdf"
        success = to_pdf(report, pdf_path)
        if success:
            result.pdf_path = str(pdf_path)

    # ── Phase 8: Persist to SQLite ────────────────────────────────────────
    logger.info("Phase 8: Persisting to scan history")
    try:
        db.save_scan(
            custody.report_id, pcap_path, meta.sha256,
            meta.packet_count, len(sessions),
        )
        for host, grade in host_grades.items():
            db.save_host_grade(
                custody.report_id, host, grade.grade, grade.score, grade.finding_counts
            )
        all_findings = [f for sr in session_results for f in sr.findings]
        db.save_findings(custody.report_id, all_findings)
    except Exception as exc:
        logger.warning("SQLite persistence failed (non-fatal): %s", exc)
    finally:
        db.close()

    # ── Optional enrichment ───────────────────────────────────────────────
    if config.enable_enrichment:
        logger.info("Phase 9: Enrichment (optional)")
        try:
            from securemailscope.enrichment import run_enrichment
            run_enrichment(report, session_results)
        except Exception as exc:
            logger.warning("Enrichment failed (non-fatal, skipped): %s", exc)

    result.report = report
    logger.info(
        "Analysis complete: %d sessions, %d findings",
        result.session_count, result.finding_count,
    )
    return result


def _run_ml(session_results: list[SessionAnalysisResult], config: PipelineConfig) -> None:
    """Train (inline, weak-supervised) and run the ML models."""
    # Build feature matrix
    fvecs = []
    for sr in session_results:
        fv = build_feature_vector(sr.session, sr.tls, sr.chain)
        fvecs.append(fv)
    feature_matrix = np.stack(fvecs)

    # Derive weak-supervision labels from rule engine
    rule_labels = []
    severity_order = ["informational", "low", "medium", "high", "critical"]
    for sr in session_results:
        if not sr.findings:
            lab = "low"
        else:
            worst = max(sr.findings, key=lambda f: severity_order.index(f.severity.lower()))
            lab = worst.severity.lower()
        rule_labels.append(lab)

    # Risk classifier
    classifier = RiskClassifier()
    loaded = classifier.load()
    if not loaded:
        # Train on this batch (weak supervision)
        classifier.train_from_rule_labels(feature_matrix, rule_labels)
        try:
            classifier.save()
        except Exception as exc:
            logger.debug("Could not save classifier: %s", exc)

    # Anomaly detector
    anomaly = AnomalyDetector()
    anomaly_loaded = anomaly.load()
    if not anomaly_loaded and config.enable_anomaly:
        anomaly.fit(feature_matrix)
        try:
            anomaly.save()
        except Exception as exc:
            logger.debug("Could not save anomaly detector: %s", exc)

    # Score each session
    for i, sr in enumerate(session_results):
        fv = fvecs[i]

        label, conf, factors = classifier.predict(fv)
        sr.ml_risk_label = label
        sr.ml_confidence = conf

        # Attach contributing factors to ML-flagged findings
        if label in ("high", "critical") and factors:
            ml_finding_added = False
            for f in sr.findings:
                f.contributing_factors = factors
                ml_finding_added = True
            if not ml_finding_added and label == "critical":
                # ML found something rules didn't — create an ML finding
                from securemailscope.rules.engine import Finding
                import uuid
                ml_f = Finding(
                    id="ml-risk-classifier",
                    finding_id=str(uuid.uuid4()),
                    session_id=sr.session.session_id,
                    host=sr.session.host_key,
                    category="ml-risk",
                    severity=label,
                    description=f"ML classifier flagged session as {label}-risk",
                    evidence_ref={"packet_number": sr.session.packet_refs[0] if sr.session.packet_refs else 0},
                    contributing_factors=factors,
                    ml_flagged=True,
                )
                ml_f.remediation = get_remediation("ml-risk", sr.session.banner)
                sr.findings.append(ml_f)

        if config.enable_anomaly:
            is_anom, anom_score = anomaly.score(fv)
            sr.anomaly_detected = is_anom
            sr.anomaly_score = anom_score
            if is_anom:
                import uuid
                from securemailscope.rules.engine import Finding
                anom_f = Finding(
                    id="ml-anomaly",
                    finding_id=str(uuid.uuid4()),
                    session_id=sr.session.session_id,
                    host=sr.session.host_key,
                    category="ml-anomaly",
                    severity="medium",
                    description=f"Session flagged as anomalous by IsolationForest (score={anom_score:.3f})",
                    evidence_ref={"packet_number": sr.session.packet_refs[0] if sr.session.packet_refs else 0},
                    contributing_factors=["anomaly-score", "isolation-forest"],
                    ml_flagged=True,
                    anomaly_score=anom_score,
                )
                anom_f.remediation = "Investigate session for unusual TLS behavior or novel misconfiguration."
                sr.findings.append(anom_f)
