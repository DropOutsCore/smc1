"""
securemailscope/api/app.py
----------------------------
FastAPI application — wraps the analysis pipeline as a REST API.

The JSON contract is locked per PRD §4.9 to allow a React frontend
to replace the Streamlit dashboard without backend changes.

Endpoints:
  POST /analyze       — accept a PCAP file, run pipeline, return JSON report
  GET  /history/{host} — return grade history for a host
  GET  /reports/{report_id} — return a stored report by ID
  GET  /health        — liveness check
"""

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

app = FastAPI(
    title="SecureMailScope API",
    version="1.0.0",
    description=(
        "Passive email TLS forensic analysis API. "
        "Upload a PCAP file to receive a structured risk report."
    ),
)

# CORS — allow React/Streamlit frontends to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_TEMP_DIR = Path(tempfile.gettempdir()) / "securemailscope"
_TEMP_DIR.mkdir(parents=True, exist_ok=True)


@app.get("/health")
async def health() -> dict:
    """Liveness check."""
    return {"status": "ok", "service": "SecureMailScope", "version": "1.0.0"}


@app.post("/analyze")
async def analyze(
    file: UploadFile = File(..., description="PCAP, PCAPNG, or JSON report file"),
    enable_enrichment: bool = False,
    enable_ml: bool = True,
) -> JSONResponse:
    """
    Upload a PCAP file or an existing JSON report to receive/view a full forensic risk report.

    The file is written to a temporary location, analyzed, then deleted.
    The source file is never modified — read-only analysis only.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    suffix = Path(file.filename).suffix.lower()
    if suffix not in (".pcap", ".pcapng", ".json"):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{suffix}'. Only .pcap, .pcapng, and .json are accepted."
        )

    # Write uploaded bytes to a temp file
    tmp_path = _TEMP_DIR / file.filename
    try:
        contents = await file.read()
        with open(tmp_path, "wb") as f:
            f.write(contents)

        from securemailscope.pipeline import PipelineConfig, run

        config = PipelineConfig(
            output_dir=str(_TEMP_DIR),
            enable_enrichment=enable_enrichment,
            enable_ml=enable_ml,
            generate_html=False,
            generate_pdf=False,
        )
        result = run(str(tmp_path), config)

        if result.error:
            raise HTTPException(status_code=500, detail=result.error)

        return JSONResponse(content=result.report)

    finally:
        # Always clean up temp PCAP
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass


@app.get("/history/{host:path}")
async def history(host: str, limit: int = 10) -> JSONResponse:
    """Return grade history for a host (ip:port format)."""
    from securemailscope.storage.database import ScanDatabase

    db = ScanDatabase()
    try:
        records = db.get_grade_history(host, limit=limit)
    finally:
        db.close()

    return JSONResponse(content={"host": host, "history": records})


@app.get("/")
async def root() -> dict:
    return {
        "service": "SecureMailScope",
        "version": "1.0.0",
        "docs": "/docs",
        "endpoints": ["/analyze", "/history/{host}", "/health"],
    }
