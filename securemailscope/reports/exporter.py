"""
securemailscope/reports/exporter.py
--------------------------------------
HTML and PDF report export.

HTML: Jinja2 rendering of report.html.j2
PDF:  WeasyPrint (primary) → ReportLab fallback
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"

_jinja_env: Optional[Environment] = None


def _get_jinja_env() -> Environment:
    global _jinja_env
    if _jinja_env is None:
        _jinja_env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=select_autoescape(["html", "j2"]),
        )
    return _jinja_env


def to_html(report: dict) -> str:
    """Render the report dict as an HTML string."""
    env = _get_jinja_env()
    tpl = env.get_template("report.html.j2")
    return tpl.render(report=report)


def to_pdf(report: dict, output_path: str | Path) -> bool:
    """
    Render the report as a PDF file.

    Tries WeasyPrint first; falls back to a minimal ReportLab PDF.

    Returns True if PDF was generated successfully, False otherwise.
    """
    output_path = Path(output_path)
    html = to_html(report)

    # ── WeasyPrint ────────────────────────────────────────────────────────
    try:
        from weasyprint import HTML as WP_HTML  # type: ignore
        WP_HTML(string=html, base_url=str(_TEMPLATES_DIR)).write_pdf(str(output_path))
        logger.info("PDF generated with WeasyPrint: %s", output_path)
        return True
    except ImportError:
        logger.info("WeasyPrint not installed — trying ReportLab fallback.")
    except Exception as exc:
        logger.warning("WeasyPrint failed (%s) — trying ReportLab fallback.", exc)

    # ── ReportLab fallback ────────────────────────────────────────────────
    try:
        from reportlab.lib.pagesizes import A4  # type: ignore
        from reportlab.lib.units import cm  # type: ignore
        from reportlab.lib import colors  # type: ignore
        from reportlab.platypus import (  # type: ignore
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        )
        from reportlab.lib.styles import getSampleStyleSheet  # type: ignore

        doc = SimpleDocTemplate(str(output_path), pagesize=A4)
        styles = getSampleStyleSheet()
        story = []

        story.append(Paragraph("SecureMailScope Forensic Report", styles["Title"]))
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph(f"Report ID: {report.get('report_id', '')}", styles["Normal"]))
        story.append(Paragraph(f"Generated: {report.get('generated_at', '')}", styles["Normal"]))
        story.append(Paragraph(f"Source SHA-256: {report.get('source_pcap_sha256', '')}", styles["Normal"]))
        story.append(Spacer(1, 0.5 * cm))

        for host in report.get("hosts", []):
            story.append(Paragraph(
                f"Host: {host['host']} — Grade {host['posture_grade']}",
                styles["Heading2"]
            ))
            for session in host.get("sessions", []):
                story.append(Paragraph(
                    f"{session['protocol']} {session['src_ip']}:{session['src_port']} → "
                    f"{session['dst_ip']}:{session['dst_port']}  TLS={session['tls_version']}",
                    styles["Heading3"]
                ))
                for f in session.get("findings", []):
                    story.append(Paragraph(
                        f"[{f['severity'].upper()}] {f['id']}: {f['description']}  "
                        f"(pkt #{f['evidence_ref'].get('packet_number', '?')})",
                        styles["Normal"]
                    ))
                story.append(Spacer(1, 0.2 * cm))

        doc.build(story)
        logger.info("PDF generated with ReportLab: %s", output_path)
        return True
    except ImportError:
        logger.error("Neither WeasyPrint nor ReportLab is installed. Cannot generate PDF.")
    except Exception as exc:
        logger.error("ReportLab PDF generation failed: %s", exc)

    return False
