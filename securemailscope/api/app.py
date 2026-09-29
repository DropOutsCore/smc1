"""
securemailscope/api/app.py
----------------------------
AVALOK FastAPI backend — wraps the analysis pipeline as a production REST API.

Endpoints:
  POST   /api/pcap/upload            — upload a PCAP, runs analysis, returns report_id
  GET    /api/analysis/{id}/status   — poll analysis progress
  GET    /api/analysis/{id}/result   — get the full JSON report
  GET    /api/reports                — list all stored reports
  GET    /api/reports/{id}           — get a specific report
  GET    /api/reports/{id}/download/html  — download HTML report
  GET    /api/reports/{id}/download/json  — download JSON report
  DELETE /api/reports/{id}           — delete a report
  GET    /api/health                 — liveness check
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import threading
import uuid
from pathlib import Path
from typing import Any, Optional
import time

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="AVALOK API",
    version="1.0.0",
    description="Passive Email TLS Forensic Analysis API — AVALOK",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------
_REPORTS_DIR = Path("reports_out")
_REPORTS_DIR.mkdir(parents=True, exist_ok=True)

_TEMP_DIR = Path(tempfile.gettempdir()) / "avalok"
_TEMP_DIR.mkdir(parents=True, exist_ok=True)

# In-memory analysis job store  { analysis_id: { status, progress, report, error } }
_JOBS: dict[str, dict[str, Any]] = {}
_JOBS_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_stored_reports() -> list[dict]:
    """Scan the reports_out/ directory and return summary list."""
    out = []
    for jf in sorted(_REPORTS_DIR.glob("*_report.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            with open(jf, "r", encoding="utf-8") as f:
                r = json.load(f)
            # Compute summary
            all_findings = [
                fi for h in r.get("hosts", [])
                for s in h.get("sessions", [])
                for fi in s.get("findings", [])
            ]
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for fi in all_findings:
                sev = fi.get("severity", "").lower()
                if sev in severity_counts:
                    severity_counts[sev] += 1

            worst_grade = "A"
            grade_order = ["F", "D", "C", "B", "A"]
            for h in r.get("hosts", []):
                g = h.get("posture_grade", "A")
                if grade_order.index(g) < grade_order.index(worst_grade):
                    worst_grade = g

            out.append({
                "report_id": r.get("report_id", jf.stem),
                "source_pcap_path": r.get("source_pcap_path", ""),
                "source_pcap_sha256": r.get("source_pcap_sha256", ""),
                "generated_at": r.get("generated_at", ""),
                "tool_version": r.get("tool_version", "1.0.0"),
                "worst_grade": worst_grade,
                "host_count": len(r.get("hosts", [])),
                "finding_count": len(all_findings),
                "severity_summary": severity_counts,
                "json_path": str(jf),
            })
        except Exception as exc:
            logger.warning("Could not read report %s: %s", jf, exc)
    return out


def _run_analysis_job(job_id: str, pcap_path: str, file_sha256: str) -> None:
    """Background thread: run the analysis pipeline and update _JOBS."""
    def _update(stage: str, pct: int, extra: dict | None = None):
        with _JOBS_LOCK:
            _JOBS[job_id]["stage"] = stage
            _JOBS[job_id]["progress"] = pct
            if extra:
                _JOBS[job_id].update(extra)

    try:
        _update("Validating PCAP", 5)
        time.sleep(0.2)

        _update("Computing SHA-256", 10)

        _update("Parsing packets", 20)

        from securemailscope.pipeline import PipelineConfig, run

        config = PipelineConfig(
            output_dir=str(_REPORTS_DIR),
            enable_ml=True,
            enable_anomaly=True,
            generate_html=True,
            generate_pdf=False,
        )

        _update("Reconstructing sessions", 40)
        _update("Analyzing TLS handshakes", 55)
        _update("Evaluating security rules", 70)
        _update("Running ML assessment", 80)
        _update("Calculating risk scores", 88)
        _update("Generating report", 92)

        result = run(pcap_path, config)

        if result.error:
            with _JOBS_LOCK:
                _JOBS[job_id]["status"] = "error"
                _JOBS[job_id]["error"] = result.error
            return

        if result.report:
            from securemailscope.forensics.evidence_layer import enrich_report_with_forensics
            from securemailscope.scoring.explainability import enrich_report_with_explainability
            result.report = enrich_report_with_forensics(
                result.report,
                pcap_path=pcap_path,
                pcap_sha256=file_sha256,
                analysis_id=job_id,
            )
            result.report = enrich_report_with_explainability(result.report)

        _update("Complete", 100, {
            "status": "complete",
            "report": result.report,
            "json_path": result.json_path,
            "html_path": result.html_path,
        })

    except Exception as exc:
        logger.exception("Analysis job %s failed", job_id)
        with _JOBS_LOCK:
            _JOBS[job_id]["status"] = "error"
            _JOBS[job_id]["error"] = str(exc)
    finally:
        # Clean up temp PCAP
        try:
            Path(pcap_path).unlink(missing_ok=True)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/api/health")
async def health() -> dict:
    """Liveness check."""
    return {
        "status": "ok",
        "service": "AVALOK",
        "version": "1.0.0",
        "analyzer": "SecureMailScope 1.0.0",
    }


# ---------------------------------------------------------------------------
# PCAP Upload
# ---------------------------------------------------------------------------

@app.post("/api/pcap/upload")
async def upload_pcap(
    file: UploadFile = File(..., description="PCAP or PCAPNG network capture"),
    background_tasks: BackgroundTasks = BackgroundTasks(),
) -> JSONResponse:
    """
    Upload a PCAP file and start asynchronous analysis.
    Returns an analysis_id for polling.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    suffix = Path(file.filename).suffix.lower()
    if suffix not in (".pcap", ".pcapng", ".cap"):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{suffix}'. Only .pcap, .pcapng, and .cap are accepted.",
        )

    contents = await file.read()
    file_sha256 = _sha256_bytes(contents)
    file_size = len(contents)

    # Save to temp
    analysis_id = str(uuid.uuid4())
    tmp_path = _TEMP_DIR / f"{analysis_id}{suffix}"
    with open(tmp_path, "wb") as f:
        f.write(contents)

    # Register job
    with _JOBS_LOCK:
        _JOBS[analysis_id] = {
            "analysis_id": analysis_id,
            "status": "running",
            "stage": "Uploaded",
            "progress": 0,
            "filename": file.filename,
            "file_size": file_size,
            "file_sha256": file_sha256,
            "report": None,
            "json_path": None,
            "html_path": None,
            "error": None,
        }

    # Start background analysis
    t = threading.Thread(target=_run_analysis_job, args=(analysis_id, str(tmp_path), file_sha256), daemon=True)
    t.start()

    return JSONResponse(content={
        "analysis_id": analysis_id,
        "filename": file.filename,
        "file_size": file_size,
        "file_sha256": file_sha256,
        "status": "running",
    })


# ---------------------------------------------------------------------------
# Analysis status polling
# ---------------------------------------------------------------------------

@app.get("/api/analysis/{analysis_id}/status")
async def analysis_status(analysis_id: str) -> JSONResponse:
    with _JOBS_LOCK:
        job = _JOBS.get(analysis_id)
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found")

    return JSONResponse(content={
        "analysis_id": analysis_id,
        "status": job["status"],
        "stage": job["stage"],
        "progress": job["progress"],
        "filename": job["filename"],
        "file_size": job["file_size"],
        "file_sha256": job["file_sha256"],
        "error": job.get("error"),
    })


@app.get("/api/analysis/{analysis_id}/result")
async def analysis_result(analysis_id: str) -> JSONResponse:
    with _JOBS_LOCK:
        job = _JOBS.get(analysis_id)
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found")
    if job["status"] != "complete":
        raise HTTPException(status_code=202, detail=f"Analysis not complete (status: {job['status']})")
    return JSONResponse(content=job["report"])


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

@app.get("/api/reports")
async def list_reports() -> JSONResponse:
    """List all stored analysis reports."""
    reports = _load_stored_reports()
    return JSONResponse(content={"reports": reports, "count": len(reports)})


@app.get("/api/reports/{report_id}")
async def get_report(report_id: str) -> JSONResponse:
    """Return the full JSON report by report_id."""
    # Check in-memory jobs first
    with _JOBS_LOCK:
        for job in _JOBS.values():
            if job.get("report") and (job["report"].get("report_id") == report_id or job.get("analysis_id") == report_id):
                return JSONResponse(content=job["report"])

    # Check reports_out/
    for jf in _REPORTS_DIR.glob("*_report.json"):
        try:
            with open(jf, "r", encoding="utf-8") as f:
                r = json.load(f)
            if (
                r.get("report_id") == report_id
                or jf.stem == report_id
                or jf.stem == f"{report_id}_report"
                or jf.stem.replace("_report", "") == report_id
            ):
                if "forensic_evidence_and_chain_of_custody" not in r:
                    try:
                        from securemailscope.forensics.evidence_layer import enrich_report_with_forensics
                        r = enrich_report_with_forensics(r)
                    except Exception as err:
                        logger.warning("Could not enrich forensics on %s: %s", report_id, err)
                if "explainability" not in r:
                    try:
                        from securemailscope.scoring.explainability import enrich_report_with_explainability
                        r = enrich_report_with_explainability(r)
                    except Exception as err:
                        logger.warning("Could not enrich explainability on %s: %s", report_id, err)
                return JSONResponse(content=r)
        except HTTPException:
            raise
        except Exception as exc:
            logger.warning("Error reading report file %s: %s", jf, exc)

    raise HTTPException(status_code=404, detail=f"Report {report_id} not found")


@app.get("/api/reports/{report_id}/download/json")
async def download_report_json(report_id: str) -> Response:
    for jf in _REPORTS_DIR.glob("*_report.json"):
        try:
            with open(jf, "r", encoding="utf-8") as f:
                r = json.load(f)
            if r.get("report_id") == report_id or jf.stem == report_id or jf.stem == f"{report_id}_report" or jf.stem.replace("_report", "") == report_id:
                if "forensic_evidence_and_chain_of_custody" not in r:
                    from securemailscope.forensics.evidence_layer import enrich_report_with_forensics
                    r = enrich_report_with_forensics(r)
                if "explainability" not in r:
                    from securemailscope.scoring.explainability import enrich_report_with_explainability
                    r = enrich_report_with_explainability(r)
                return Response(
                    content=json.dumps(r, indent=2),
                    media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{jf.name}"'},
                )
        except Exception:
            pass
    raise HTTPException(status_code=404, detail="Report JSON not found")


@app.get("/api/reports/{report_id}/download/html")
async def download_report_html(report_id: str) -> Response:
    # Find matching HTML
    for jf in _REPORTS_DIR.glob("*_report.json"):
        try:
            with open(jf, "r", encoding="utf-8") as f:
                r = json.load(f)
            if r.get("report_id") == report_id or jf.stem == report_id or jf.stem == f"{report_id}_report" or jf.stem.replace("_report", "") == report_id:
                if "forensic_evidence_and_chain_of_custody" not in r:
                    from securemailscope.forensics.evidence_layer import enrich_report_with_forensics
                    r = enrich_report_with_forensics(r)
                if "explainability" not in r:
                    from securemailscope.scoring.explainability import enrich_report_with_explainability
                    r = enrich_report_with_explainability(r)
                html_path = jf.with_name(jf.name.replace("_report.json", "_report.html"))
                # Always re-render or generate on the fly to reflect latest explainability layer
                from securemailscope.reports.exporter import to_html
                html_str = to_html(r)
                html_path.write_text(html_str, encoding="utf-8")
                return Response(
                    content=html_str,
                    media_type="text/html",
                    headers={"Content-Disposition": f'attachment; filename="{html_path.name}"'},
                )
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))
    raise HTTPException(status_code=404, detail="Report not found")


@app.get("/api/reports/{report_id}/download/pdf")
async def download_report_pdf(report_id: str) -> Response:
    """Generate and download a PDF forensic report."""
    report_data = None
    target_pdf_path = None

    # Find the report JSON and potential PDF path
    for jf in _REPORTS_DIR.glob("*_report.json"):
        try:
            with open(jf, "r", encoding="utf-8") as f:
                r = json.load(f)
            if r.get("report_id") == report_id or jf.stem == report_id or jf.stem == f"{report_id}_report" or jf.stem.replace("_report", "") == report_id:
                report_data = r
                target_pdf_path = jf.with_name(jf.name.replace("_report.json", "_report.pdf"))
                break
        except Exception:
            pass

    # Also check in-memory jobs
    if report_data is None:
        with _JOBS_LOCK:
            for job in _JOBS.values():
                if job.get("report") and (job["report"].get("report_id") == report_id or job.get("analysis_id") == report_id):
                    report_data = job["report"]
                    target_pdf_path = _REPORTS_DIR / f"{report_id}_report.pdf"
                    break

    if report_data is None:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")

    if "forensic_evidence_and_chain_of_custody" not in report_data:
        from securemailscope.forensics.evidence_layer import enrich_report_with_forensics
        report_data = enrich_report_with_forensics(report_data)
    if "explainability" not in report_data:
        from securemailscope.scoring.explainability import enrich_report_with_explainability
        report_data = enrich_report_with_explainability(report_data)

    # Generate PDF directly to target location or temp (always refresh to include latest explainability)
    try:
        from securemailscope.reports.exporter import to_pdf
        pdf_out = target_pdf_path or (_REPORTS_DIR / f"avalok_{report_id[:8]}_report.pdf")
        success = to_pdf(report_data, pdf_out)
        if not success or not pdf_out.exists():
            raise HTTPException(
                status_code=500,
                detail="PDF generation failed. Ensure reportlab is installed: pip install reportlab",
            )

        return FileResponse(
            path=str(pdf_out),
            media_type="application/pdf",
            filename=pdf_out.name,
            headers={"Content-Disposition": f'attachment; filename="{pdf_out.name}"'},
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("PDF generation error for report %s", report_id)
        raise HTTPException(status_code=500, detail=f"PDF generation error: {exc}")


@app.delete("/api/reports/{report_id}")
async def delete_report(report_id: str) -> JSONResponse:
    deleted = False
    for jf in _REPORTS_DIR.glob("*_report.json"):
        try:
            with open(jf, "r", encoding="utf-8") as f:
                r = json.load(f)
            if r.get("report_id") == report_id or jf.stem == report_id or jf.stem == f"{report_id}_report" or jf.stem.replace("_report", "") == report_id:
                jf.unlink(missing_ok=True)
                html_path = jf.with_name(jf.name.replace("_report.json", "_report.html"))
                html_path.unlink(missing_ok=True)
                pdf_path = jf.with_name(jf.name.replace("_report.json", "_report.pdf"))
                pdf_path.unlink(missing_ok=True)
                deleted = True
                break
        except Exception:
            pass
    if not deleted:
        raise HTTPException(status_code=404, detail="Report not found")
    # Also remove from in-memory jobs
    with _JOBS_LOCK:
        for jid, job in list(_JOBS.items()):
            if job.get("report") and job["report"].get("report_id") == report_id:
                del _JOBS[jid]
                break
    return JSONResponse(content={"deleted": True, "report_id": report_id})


# ---------------------------------------------------------------------------
# Legacy endpoints (backward compat)
# ---------------------------------------------------------------------------

@app.post("/analyze")
async def analyze_legacy(
    file: UploadFile = File(..., description="PCAP, PCAPNG, or JSON report file"),
    enable_enrichment: bool = False,
    enable_ml: bool = True,
) -> JSONResponse:
    """Legacy synchronous analyze endpoint (kept for Streamlit compatibility)."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    suffix = Path(file.filename).suffix.lower()
    if suffix not in (".pcap", ".pcapng", ".json"):
        raise HTTPException(status_code=400, detail=f"Unsupported type '{suffix}'")

    tmp_path = _TEMP_DIR / file.filename
    try:
        contents = await file.read()
        with open(tmp_path, "wb") as f:
            f.write(contents)

        from securemailscope.pipeline import PipelineConfig, run
        config = PipelineConfig(
            output_dir=str(_REPORTS_DIR),
            enable_enrichment=enable_enrichment,
            enable_ml=enable_ml,
            generate_html=True,
            generate_pdf=False,
        )
        result = run(str(tmp_path), config)
        if result.error:
            raise HTTPException(status_code=500, detail=result.error)
        return JSONResponse(content=result.report)
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass


@app.get("/history/{host:path}")
async def history_legacy(host: str, limit: int = 10) -> JSONResponse:
    from securemailscope.storage.database import ScanDatabase
    db = ScanDatabase()
    try:
        records = db.get_grade_history(host, limit=limit)
    finally:
        db.close()
    return JSONResponse(content={"host": host, "history": records})


@app.get("/health")
async def health_legacy() -> dict:
    return {"status": "ok", "service": "SecureMailScope", "version": "1.0.0"}


@app.get("/")
async def root() -> dict:
    return {
        "service": "AVALOK",
        "version": "1.0.0",
        "docs": "/docs",
        "frontend": "http://localhost:5173",
        "endpoints": [
            "/api/pcap/upload",
            "/api/analysis/{id}/status",
            "/api/analysis/{id}/result",
            "/api/reports",
            "/api/reports/{id}",
            "/api/health",
        ],
    }
