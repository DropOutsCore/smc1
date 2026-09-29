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


def _clean_str(val: Any) -> str:
    """Sanitize and XML-escape strings for ReportLab Paragraph flowables."""
    if val is None:
        return ""
    s = str(val)
    # Remove non-printable / binary control chars while keeping spaces & newlines
    cleaned = "".join(
        ch if (ch in ("\n", "\t") or (ch >= " " and ord(ch) < 127) or ord(ch) >= 160) else " "
        for ch in s
    )
    return (
        cleaned.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _generate_reportlab_pdf(report: dict, output_path: Path) -> bool:
    """Generate a high-fidelity forensic PDF report using ReportLab."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
        )
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.pdfgen import canvas

        # Page setup
        PAGE_WIDTH, PAGE_HEIGHT = A4
        MARGIN = 36  # 0.5 inch margins -> 523.27 pt usable width
        USABLE_WIDTH = PAGE_WIDTH - (MARGIN * 2)

        # ── Color Palette ───────────────────────────────────────────────────
        PRIMARY = colors.HexColor("#0B2A20")      # Deep forest slate
        ACCENT = colors.HexColor("#10B981")       # Emerald
        TEXT_DARK = colors.HexColor("#0F172A")    # Slate 900
        TEXT_MUTED = colors.HexColor("#475569")   # Slate 600
        BORDER_COLOR = colors.HexColor("#CBD5E1") # Slate 300
        BG_LIGHT = colors.HexColor("#F8FAFC")     # Slate 50
        BG_CARD = colors.HexColor("#F1F5F9")      # Slate 100
        CODE_BG = colors.HexColor("#1E293B")      # Dark slate for code
        WHITE = colors.HexColor("#FFFFFF")

        SEV_CRITICAL = colors.HexColor("#DC2626") # Red 600
        SEV_HIGH = colors.HexColor("#D97706")     # Amber 600
        SEV_MEDIUM = colors.HexColor("#2563EB")   # Blue 600
        SEV_LOW = colors.HexColor("#059669")      # Emerald 600
        SEV_INFO = colors.HexColor("#64748B")     # Slate 500

        GRADE_COLORS = {
            "A+": colors.HexColor("#059669"),
            "A": colors.HexColor("#10B981"),
            "B": colors.HexColor("#2563EB"),
            "C": colors.HexColor("#D97706"),
            "D": colors.HexColor("#EA580C"),
            "E": colors.HexColor("#E11D48"),
            "F": colors.HexColor("#DC2626"),
        }

        # ── Two-pass Canvas for Running Header & Footer ─────────────────────
        report_id_str = report.get("report_id", "")[:8]
        report_sha = report.get("custody", {}).get("report_sha256") or report.get("report_sha256", "")

        class NumberedCanvas(canvas.Canvas):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self._saved_page_states = []

            def showPage(self):
                self._saved_page_states.append(dict(self.__dict__))
                self._startPage()

            def save(self):
                num_pages = len(self._saved_page_states)
                for state in self._saved_page_states:
                    self.__dict__.update(state)
                    self.draw_decorations(num_pages)
                    super().showPage()
                super().save()

            def draw_decorations(self, total_pages):
                self.saveState()
                self.setFont("Helvetica-Bold", 7.5)
                self.setFillColor(TEXT_MUTED)

                # Running Header (pages after page 1)
                if self._pageNumber > 1:
                    self.drawString(MARGIN, PAGE_HEIGHT - 26, "AVALOK SECUREMAILSCOPE")
                    self.setFont("Helvetica", 7.5)
                    self.drawString(MARGIN + 120, PAGE_HEIGHT - 26, "|   Passive Email TLS Forensic Analysis Report")
                    self.drawRightString(PAGE_WIDTH - MARGIN, PAGE_HEIGHT - 26, f"Ref: #{report_id_str}")
                    self.setStrokeColor(BORDER_COLOR)
                    self.setLineWidth(0.5)
                    self.line(MARGIN, PAGE_HEIGHT - 30, PAGE_WIDTH - MARGIN, PAGE_HEIGHT - 30)

                # Running Footer (all pages)
                self.setStrokeColor(BORDER_COLOR)
                self.setLineWidth(0.5)
                self.line(MARGIN, 34, PAGE_WIDTH - MARGIN, 34)

                self.setFont("Helvetica-Bold", 7)
                self.setFillColor(PRIMARY)
                self.drawString(MARGIN, 22, "CONFIDENTIAL & FORENSIC EVIDENCE")
                self.setFont("Helvetica", 7)
                self.setFillColor(TEXT_MUTED)
                sha_label = f"  |  SHA-256: {report_sha[:16]}..." if report_sha else ""
                self.drawString(MARGIN + 160, 22, sha_label)
                self.drawRightString(PAGE_WIDTH - MARGIN, 22, f"Page {self._pageNumber} of {total_pages}")
                self.restoreState()

        # ── Document Template & Styles ──────────────────────────────────────
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            leftMargin=MARGIN,
            rightMargin=MARGIN,
            topMargin=42,
            bottomMargin=46,
        )

        base_styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "ReportTitle",
            parent=base_styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            textColor=WHITE,
            alignment=0,
            spaceAfter=3,
        )
        subtitle_style = ParagraphStyle(
            "ReportSubtitle",
            parent=base_styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#A7F3D0"),
            alignment=0,
        )
        sec_h1 = ParagraphStyle(
            "SecH1",
            parent=base_styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            textColor=PRIMARY,
            spaceBefore=12,
            spaceAfter=6,
            keepWithNext=True,
        )
        sec_h2 = ParagraphStyle(
            "SecH2",
            parent=base_styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=10.5,
            leading=14,
            textColor=TEXT_DARK,
            spaceBefore=8,
            spaceAfter=4,
            keepWithNext=True,
        )
        body_style = ParagraphStyle(
            "ReportBody",
            parent=base_styles["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=TEXT_DARK,
        )
        body_muted = ParagraphStyle(
            "ReportBodyMuted",
            parent=body_style,
            textColor=TEXT_MUTED,
        )
        code_style = ParagraphStyle(
            "ReportCode",
            parent=base_styles["Normal"],
            fontName="Courier",
            fontSize=7,
            leading=9,
            textColor=WHITE,
        )
        mono_small = ParagraphStyle(
            "ReportMonoSmall",
            parent=base_styles["Normal"],
            fontName="Courier",
            fontSize=7,
            leading=9,
            textColor=TEXT_DARK,
        )

        story = []

        # ── 1. Top Brand Banner ─────────────────────────────────────────────
        banner_content = [
            [
                Paragraph("🔒 AVALOK SECUREMAILSCOPE", title_style),
                Paragraph("Passive Email TLS Forensic Analysis & Compliance Inspection", subtitle_style),
            ]
        ]
        banner_table = Table(
            [[
                Paragraph("<b>🔒 AVALOK SECUREMAILSCOPE</b>", title_style),
                Paragraph(f"<b>REPORT #{report_id_str}</b><br/>{_clean_str(report.get('generated_at', ''))[:19]}", ParagraphStyle("RightHdr", parent=subtitle_style, alignment=2))
            ], [
                Paragraph("Passive Email TLS Forensics • NIST SP 800-52 • RFC 8996 Compliance", subtitle_style),
                Paragraph("CONFIDENTIAL EVIDENCE", ParagraphStyle("Badge", parent=subtitle_style, alignment=2, fontName="Helvetica-Bold"))
            ]],
            colWidths=[USABLE_WIDTH * 0.65, USABLE_WIDTH * 0.35],
        )
        banner_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), PRIMARY),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("RIGHTPADDING", (0, 0), (-1, -1), 12),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(banner_table)
        story.append(Spacer(1, 10))

        # ── 2. Chain of Custody & Forensic Evidence ─────────────────────────
        story.append(Paragraph("1. FORENSIC EVIDENCE & CHAIN OF CUSTODY", sec_h1))

        custody = report.get("custody", {})
        forensic_meta = report.get("forensic_evidence_and_chain_of_custody", {})
        pcap_path = custody.get("source_pcap_path") or report.get("source_pcap_path") or forensic_meta.get("source_pcap", "N/A")
        pcap_name = Path(pcap_path).name if pcap_path and pcap_path != "N/A" else "Unknown"
        pcap_size = custody.get("source_pcap_size_bytes") or report.get("source_pcap_size_bytes", 0)
        pcap_sha = custody.get("source_pcap_sha256") or report.get("source_pcap_sha256") or forensic_meta.get("pcap_sha256", "N/A")
        analyst = custody.get("analyst_host") or report.get("analyst_host", "AVALOK Automated Engine")
        tool_ver = custody.get("tool_version") or report.get("tool_version", "1.0.0")
        analysis_id_val = report.get("analysis_id") or forensic_meta.get("analysis_id") or report.get("report_id", "")
        offline_status = forensic_meta.get("passive_offline_status") or custody.get("passive_offline_status") or "PASSIVE_OFFLINE (Air-Gapped)"
        integrity_stmt = forensic_meta.get("integrity_statement") or custody.get("integrity_statement") or "No active network connections were made during analysis."

        # Integrity statement callout banner
        integrity_banner = Table(
            [[
                Paragraph(f"<b>🛡️ INTEGRITY STATEMENT:</b> {_clean_str(integrity_stmt)}", ParagraphStyle("IntegTxt", parent=body_style, textColor=colors.HexColor("#065F46"), fontName="Helvetica-Bold")),
                Paragraph(f"<b>{_clean_str(offline_status)}</b>", ParagraphStyle("IntegBdg", parent=body_style, alignment=2, textColor=colors.HexColor("#047857"), fontName="Helvetica-Bold", fontSize=7.5))
            ]],
            colWidths=[USABLE_WIDTH * 0.68, USABLE_WIDTH * 0.32]
        )
        integrity_banner.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#ECFDF5")),
            ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#10B981")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(integrity_banner)
        story.append(Spacer(1, 5))

        custody_data = [
            [
                Paragraph("<b>Report ID:</b>", body_style),
                Paragraph(_clean_str(report.get("report_id", "")), mono_small),
                Paragraph("<b>Analysis ID:</b>", body_style),
                Paragraph(_clean_str(analysis_id_val), mono_small),
            ],
            [
                Paragraph("<b>Source PCAP:</b>", body_style),
                Paragraph(_clean_str(f"{pcap_name} ({pcap_size:,} bytes)" if pcap_size else pcap_name), body_style),
                Paragraph("<b>Generated At:</b>", body_style),
                Paragraph(_clean_str(report.get("generated_at", "")), body_style),
            ],
            [
                Paragraph("<b>PCAP SHA-256:</b>", body_style),
                Paragraph(_clean_str(pcap_sha), mono_small),
                Paragraph("<b>Analyzer Version:</b>", body_style),
                Paragraph(_clean_str(f"SecureMailScope v{tool_ver}"), body_style),
            ],
            [
                Paragraph("<b>Operational Mode:</b>", body_style),
                Paragraph("<font color='#059669'><b>100% Offline / Air-Gapped (Read-Only)</b></font>", body_style),
                Paragraph("<b>Report SHA-256:</b>", body_style),
                Paragraph(_clean_str(report_sha or "Pending verification"), mono_small),
            ],
        ]

        col_w = [USABLE_WIDTH * 0.17, USABLE_WIDTH * 0.40, USABLE_WIDTH * 0.16, USABLE_WIDTH * 0.27]
        custody_tbl = Table(custody_data, colWidths=col_w)
        custody_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), BG_LIGHT),
            ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(custody_tbl)
        story.append(Spacer(1, 10))

        # ── 3. Executive Summary & Posture Summary ───────────────────────────
        story.append(Paragraph("2. EXECUTIVE SUMMARY & POSTURE ASSESSMENT", sec_h1))

        hosts = report.get("hosts", [])
        total_sessions = sum(len(h.get("sessions", [])) for h in hosts)
        all_findings = [
            f for h in hosts for s in h.get("sessions", []) for f in s.get("findings", [])
        ]
        critical_count = sum(1 for f in all_findings if f.get("severity", "").lower() == "critical")
        high_count = sum(1 for f in all_findings if f.get("severity", "").lower() == "high")
        med_count = sum(1 for f in all_findings if f.get("severity", "").lower() == "medium")
        low_count = sum(1 for f in all_findings if f.get("severity", "").lower() == "low")

        summary_cards = [
            [
                Paragraph("<b>HOSTS ANALYZED</b>", body_muted),
                Paragraph("<b>SESSIONS</b>", body_muted),
                Paragraph("<b>TOTAL FINDINGS</b>", body_muted),
                Paragraph("<b>CRITICAL</b>", ParagraphStyle("C", parent=body_style, textColor=SEV_CRITICAL, fontName="Helvetica-Bold")),
                Paragraph("<b>HIGH</b>", ParagraphStyle("H", parent=body_style, textColor=SEV_HIGH, fontName="Helvetica-Bold")),
                Paragraph("<b>MEDIUM</b>", ParagraphStyle("M", parent=body_style, textColor=SEV_MEDIUM, fontName="Helvetica-Bold")),
                Paragraph("<b>LOW</b>", ParagraphStyle("L", parent=body_style, textColor=SEV_LOW, fontName="Helvetica-Bold")),
            ],
            [
                Paragraph(f"<font size='14'><b>{len(hosts)}</b></font>", body_style),
                Paragraph(f"<font size='14'><b>{total_sessions}</b></font>", body_style),
                Paragraph(f"<font size='14'><b>{len(all_findings)}</b></font>", body_style),
                Paragraph(f"<font size='14' color='#DC2626'><b>{critical_count}</b></font>", body_style),
                Paragraph(f"<font size='14' color='#D97706'><b>{high_count}</b></font>", body_style),
                Paragraph(f"<font size='14' color='#2563EB'><b>{med_count}</b></font>", body_style),
                Paragraph(f"<font size='14' color='#059669'><b>{low_count}</b></font>", body_style),
            ]
        ]
        w7 = USABLE_WIDTH / 7
        summary_tbl = Table(summary_cards, colWidths=[w7] * 7)
        summary_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), BG_CARD),
            ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, BORDER_COLOR),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(summary_tbl)
        story.append(Spacer(1, 8))

        # Host Posture Table
        host_rows = [
            [
                Paragraph("<b>Host / Endpoint</b>", body_style),
                Paragraph("<b>Posture Grade</b>", body_style),
                Paragraph("<b>Risk Score</b>", body_style),
                Paragraph("<b>Findings Breakdown</b>", body_style),
                Paragraph("<b>Posture Delta</b>", body_style),
            ]
        ]
        for h in hosts:
            grade = h.get("posture_grade", "A")
            label = h.get("posture_label", "")
            grade_color = GRADE_COLORS.get(grade, PRIMARY)
            fs = h.get("finding_summary", {})
            f_str = f"Crit: {fs.get('critical', 0)} | High: {fs.get('high', 0)} | Med: {fs.get('medium', 0)} | Low: {fs.get('low', 0)}"

            host_rows.append([
                Paragraph(f"<b>{_clean_str(h.get('host', 'Unknown'))}</b>", body_style),
                Paragraph(f"<font size='11' color='{grade_color.hexval()}'><b>Grade {grade}</b></font><br/><font size='7' color='#475569'>{_clean_str(label)}</font>", body_style),
                Paragraph(f"{h.get('posture_score', 0)} / 100", body_style),
                Paragraph(_clean_str(f_str), body_style),
                Paragraph(_clean_str(h.get("grade_delta", "Initial scan")), body_muted),
            ])

        host_tbl = Table(
            host_rows,
            colWidths=[USABLE_WIDTH * 0.28, USABLE_WIDTH * 0.16, USABLE_WIDTH * 0.12, USABLE_WIDTH * 0.24, USABLE_WIDTH * 0.20],
        )
        host_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(host_tbl)
        story.append(Spacer(1, 10))

        # TLS 1.3 visibility note if applicable
        vis_note = report.get("tls13_visibility_note")
        if vis_note:
            note_tbl = Table(
                [[
                    Paragraph(
                        f"<b>ℹ PASSIVE TLS 1.3 VISIBILITY NOTE:</b> {_clean_str(vis_note)}",
                        ParagraphStyle("NoteStyle", parent=body_style, textColor=colors.HexColor("#1E40AF"))
                    )
                ]],
                colWidths=[USABLE_WIDTH]
            )
            note_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EFF6FF")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#93C5FD")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ]))
            story.append(note_tbl)
            story.append(Spacer(1, 10))

        # ── 4. Detailed Host & Session Findings ──────────────────────────────
        story.append(Paragraph("3. SESSION FORENSICS & SECURITY FINDINGS", sec_h1))

        sec_idx = 0
        for host in hosts:
            h_name = host.get("host", "Unknown Host")
            h_grade = host.get("posture_grade", "A")
            h_label = host.get("posture_label", "")
            h_color = GRADE_COLORS.get(h_grade, PRIMARY)

            story.append(Paragraph(
                f"<b>Host:</b> {h_name}  —  <font color='{h_color.hexval()}'><b>Grade {h_grade} ({h_label})</b> (Score: {host.get('posture_score', 0)})</font>",
                sec_h2
            ))

            why_grade = host.get("why_this_grade")
            if why_grade:
                summary_text = _clean_str(why_grade.get("summary", ""))
                bracket = why_grade.get("threshold_bracket", "")
                grade_box = [
                    [
                        Paragraph(f"<b>🛡️ SECURITY POSTURE GRADE: {h_grade} — {h_label.upper()} (Risk Score: {host.get('posture_score', 0)}/100, Bracket: {bracket})</b><br/><font color='#334155'>{summary_text}</font>", body_style),
                    ]
                ]
                grade_box_tbl = Table(grade_box, colWidths=[USABLE_WIDTH])
                grade_box_tbl.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EFF6FF")),
                    ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#60A5FA")),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ]))
                story.append(grade_box_tbl)
                story.append(Spacer(1, 4))

            host_why = host.get("why_this_score")
            if not host_why:
                try:
                    from securemailscope.scoring.explainability import explain_host_score
                    host_why = explain_host_score(host)
                except Exception:
                    host_why = None

            if host_why and host_why.get("factor_count", 0) > 0:
                h_tree_text = _clean_str(host_why.get("ascii_tree", "")).replace(" ", "&nbsp;").replace("\n", "<br/>")
                h_tree_tbl = Table(
                    [[
                        Paragraph(f"<b>🔍 Host Posture Score Breakdown:</b> {host_why.get('posture_score', 0)} / 100 (Grade {host_why.get('posture_grade', 'A')}) — {host_why.get('factor_count', 0)} security findings mapped to score contributions.<br/><br/><font color='#10B981'>{h_tree_text}</font>", code_style)
                    ]],
                    colWidths=[USABLE_WIDTH]
                )
                h_tree_tbl.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), CODE_BG),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#334155")),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ]))
                story.append(h_tree_tbl)
                story.append(Spacer(1, 4))

            sessions = host.get("sessions", [])
            for session in sessions:
                sec_idx += 1
                proto = session.get("protocol", "SMTP")
                src = f"{session.get('src_ip', '')}:{session.get('src_port', '')}"
                dst = f"{session.get('dst_ip', '')}:{session.get('dst_port', '')}"
                tls_ver = session.get("tls_version", "None")
                cipher = session.get("cipher_suite", "None")
                pfs = "YES (PFS)" if session.get("pfs") else "NO (No PFS)"
                kex = session.get("key_exchange", "N/A")
                sni = session.get("sni") or "None"
                ml_label = session.get("ml_risk_label", "N/A")
                ml_conf = session.get("ml_confidence", 0.0)
                findings = session.get("findings", [])

                # Session Overview Table
                sess_info = [
                    [
                        Paragraph(f"<b>Session #{sec_idx}: {proto}</b>", ParagraphStyle("SessHdr", parent=body_style, fontName="Helvetica-Bold", textColor=PRIMARY)),
                        Paragraph(f"<b>Flow:</b> {_clean_str(src)} → {_clean_str(dst)}", body_style),
                        Paragraph(f"<b>TLS Version:</b> {_clean_str(tls_ver)}", body_style),
                        Paragraph(f"<b>PFS:</b> {_clean_str(pfs)}", body_style),
                    ],
                    [
                        Paragraph(f"<b>Cipher:</b> {_clean_str(cipher)}", mono_small),
                        Paragraph(f"<b>Key Exch:</b> {_clean_str(kex)}", body_style),
                        Paragraph(f"<b>SNI:</b> {_clean_str(sni)}", body_style),
                        Paragraph(f"<b>ML Risk:</b> {_clean_str(ml_label)} ({ml_conf:.0%})", body_style),
                    ]
                ]
                sess_tbl = Table(
                    sess_info,
                    colWidths=[USABLE_WIDTH * 0.28, USABLE_WIDTH * 0.32, USABLE_WIDTH * 0.20, USABLE_WIDTH * 0.20],
                )
                sess_tbl.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), BG_CARD),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94A3B8")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CBD5E1")),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]))
                story.append(sess_tbl)
                story.append(Spacer(1, 4))

                # ── Why This Score? (Explainable AI & Risk Breakdown) ──────────────────
                sess_why = session.get("why_this_score")
                if not sess_why:
                    try:
                        from securemailscope.scoring.explainability import explain_session_score
                        sess_why = explain_session_score(session)
                    except Exception:
                        sess_why = None

                if sess_why:
                    why_flowables = []
                    score_val = sess_why.get("risk_score", 0)
                    sev_val = sess_why.get("severity", "clean").upper()
                    factors = sess_why.get("contributing_factors", [])

                    why_hdr = Table(
                        [[
                            Paragraph(f"<b>🔍 WHY THIS SCORE? — Transparent Risk Reasoning</b>", ParagraphStyle("WhyHdr", parent=body_style, textColor=PRIMARY, fontName="Helvetica-Bold")),
                            Paragraph(f"<b>Risk Score: {score_val} / 100 ({sev_val})</b>", ParagraphStyle("WhyScoreBdg", parent=body_style, alignment=2, textColor=PRIMARY, fontName="Helvetica-Bold")),
                        ]],
                        colWidths=[USABLE_WIDTH * 0.65, USABLE_WIDTH * 0.35]
                    )
                    why_hdr.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F0FDF4")),
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#86EFAC")),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ]))
                    why_flowables.append(why_hdr)

                    # ASCII Tree
                    tree_str = sess_why.get("ascii_tree", "")
                    if tree_str:
                        ascii_html = _clean_str(tree_str).replace(" ", "&nbsp;").replace("\n", "<br/>")
                        tree_tbl = Table(
                            [[Paragraph(f"<font color='#34D399'>{ascii_html}</font>", code_style)]],
                            colWidths=[USABLE_WIDTH]
                        )
                        tree_tbl.setStyle(TableStyle([
                            ("BACKGROUND", (0, 0), (-1, -1), CODE_BG),
                            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#334155")),
                            ("TOPPADDING", (0, 0), (-1, -1), 4),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                            ("LEFTPADDING", (0, 0), (-1, -1), 6),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                        ]))
                        why_flowables.append(tree_tbl)

                    # Contributing factors table
                    if factors:
                        factor_rows = [
                            [
                                Paragraph("<b>Finding / Feature</b>", body_style),
                                Paragraph("<b>Observed on Wire</b>", body_style),
                                Paragraph("<b>Impact</b>", body_style),
                                Paragraph("<b>Severity</b>", body_style),
                                Paragraph("<b>Evidence Ref</b>", body_style),
                                Paragraph("<b>Reason & Rationale</b>", body_style),
                            ]
                        ]
                        for factor in factors:
                            f_sev = factor.get("severity", "medium").lower()
                            f_sev_c = {
                                "critical": SEV_CRITICAL,
                                "high": SEV_HIGH,
                                "medium": SEV_MEDIUM,
                                "low": SEV_LOW,
                            }.get(f_sev, SEV_INFO)

                            factor_rows.append([
                                Paragraph(f"<b>{_clean_str(factor.get('feature', ''))}</b><br/><font color='#64748B'>{_clean_str(factor.get('rule_id', ''))}</font>", body_style),
                                Paragraph(f"<font color='#B45309'><b>{_clean_str(factor.get('observed_value', ''))}</b></font>", mono_small),
                                Paragraph(f"<font color='#DC2626'><b>+{factor.get('score_contribution', 0)}</b></font>", body_style),
                                Paragraph(f"<font color='{f_sev_c.hexval()}'><b>[{f_sev.upper()}]</b></font>", body_style),
                                Paragraph(_clean_str(factor.get("evidence_reference", "")), mono_small),
                                Paragraph(_clean_str(factor.get("short_explanation", "")), body_style),
                            ])

                        factor_tbl = Table(
                            factor_rows,
                            colWidths=[USABLE_WIDTH * 0.22, USABLE_WIDTH * 0.16, USABLE_WIDTH * 0.09, USABLE_WIDTH * 0.12, USABLE_WIDTH * 0.16, USABLE_WIDTH * 0.25]
                        )
                        factor_tbl.setStyle(TableStyle([
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
                            ("BACKGROUND", (0, 1), (-1, -1), BG_LIGHT),
                            ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CBD5E1")),
                            ("TOPPADDING", (0, 0), (-1, -1), 3),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                            ("LEFTPADDING", (0, 0), (-1, -1), 5),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ]))
                        why_flowables.append(factor_tbl)

                    # ── Separated ML Anomaly Assessment ──
                    ml_data = session.get("ml_anomaly_assessment") or sess_why.get("ml_anomaly_assessment")
                    if ml_data:
                        ml_detected = ml_data.get("is_model_anomaly", False)
                        ml_label = str(ml_data.get("ml_risk_label", "low")).upper()
                        ml_conf = ml_data.get("ml_confidence", 0.0)
                        ml_score = ml_data.get("anomaly_score", 0.0)
                        ml_arch = ml_data.get("model_architecture", "RandomForest + IsolationForest")
                        ml_note = ml_data.get("score_isolation_note", "ML assessment runs in parallel as a secondary heuristic and does not inflate deterministic rule scores.")

                        ml_tbl = Table(
                            [[
                                Paragraph(
                                    f"<b>🤖 ML ANOMALY ASSESSMENT (INDEPENDENT STATISTICAL LAYER)</b><br/>"
                                    f"<font color='#475569'>{_clean_str(ml_note)}</font><br/>"
                                    f"Risk Label: <b>{_clean_str(ml_label)}</b> ({ml_conf:.0%} conf)  |  "
                                    f"Anomaly Detected: <b>{'YES' if ml_detected else 'NO'}</b>  |  "
                                    f"Score: <b>{ml_score:.3f}</b>  |  "
                                    f"Architecture: <b>{_clean_str(ml_arch)}</b>",
                                    ParagraphStyle("MLPdfStyle", parent=body_style, fontSize=7, leading=9)
                                )
                            ]],
                            colWidths=[USABLE_WIDTH]
                        )
                        ml_tbl.setStyle(TableStyle([
                            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EFF6FF")),
                            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#93C5FD")),
                            ("TOPPADDING", (0, 0), (-1, -1), 4),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                            ("LEFTPADDING", (0, 0), (-1, -1), 6),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                        ]))
                        why_flowables.append(ml_tbl)

                    why_flowables.append(Spacer(1, 4))
                    story.append(KeepTogether(why_flowables))

                # Findings for this session
                if not findings:
                    clean_row = Table(
                        [[Paragraph("<font color='#059669'><b>✓ No security vulnerabilities or policy violations detected in this session.</b></font>", body_style)]],
                        colWidths=[USABLE_WIDTH]
                    )
                    clean_row.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#ECFDF5")),
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#A7F3D0")),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ]))
                    story.append(clean_row)
                    story.append(Spacer(1, 6))
                else:
                    for f in findings:
                        sev = f.get("severity", "medium").lower()
                        sev_color = {
                            "critical": SEV_CRITICAL,
                            "high": SEV_HIGH,
                            "medium": SEV_MEDIUM,
                            "low": SEV_LOW,
                        }.get(sev, SEV_INFO)

                        f_id = f.get("id", "finding")
                        f_desc = f.get("description", "")
                        f_cat = f.get("category", "General")
                        f_cwe = f.get("cwe", "N/A")
                        f_ref = f.get("reference", "N/A")
                        f_pkt = f.get("evidence_ref", {}).get("packet_number", "N/A")
                        f_remed = f.get("remediation", "")

                        finding_elements = []
                        # Finding Header
                        f_hdr = [
                            [
                                Paragraph(f"<font color='white'><b>[{sev.upper()}]</b></font>", ParagraphStyle("SevBdg", parent=body_style, alignment=1, textColor=WHITE, fontName="Helvetica-Bold")),
                                Paragraph(f"<b>{_clean_str(f_id)}:</b> {_clean_str(f_desc)}", body_style),
                                Paragraph(f"<b>Pkt #{f_pkt}</b>", ParagraphStyle("PktBdg", parent=body_style, alignment=2, textColor=TEXT_MUTED)),
                            ]
                        ]
                        f_hdr_tbl = Table(f_hdr, colWidths=[USABLE_WIDTH * 0.15, USABLE_WIDTH * 0.72, USABLE_WIDTH * 0.13])
                        f_hdr_tbl.setStyle(TableStyle([
                            ("BACKGROUND", (0, 0), (0, 0), sev_color),
                            ("BACKGROUND", (1, 0), (-1, 0), BG_LIGHT),
                            ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                            ("TOPPADDING", (0, 0), (-1, -1), 4),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                            ("LEFTPADDING", (0, 0), (-1, -1), 6),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ]))
                        finding_elements.append(f_hdr_tbl)

                        # Meta & Remediation
                        meta_row = [
                            Paragraph(f"<b>Category:</b> {_clean_str(f_cat)}", body_muted),
                            Paragraph(f"<b>CWE:</b> {_clean_str(f_cwe)}", body_muted),
                            Paragraph(f"<b>Standard Reference:</b> {_clean_str(f_ref)}", body_muted),
                        ]
                        meta_tbl = Table([meta_row], colWidths=[USABLE_WIDTH * 0.3, USABLE_WIDTH * 0.2, USABLE_WIDTH * 0.5])
                        meta_tbl.setStyle(TableStyle([
                            ("BACKGROUND", (0, 0), (-1, -1), BG_LIGHT),
                            ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                            ("TOPPADDING", (0, 0), (-1, -1), 3),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                            ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ]))
                        finding_elements.append(meta_tbl)

                        if f_remed:
                            remed_tbl = Table(
                                [[
                                    Paragraph(
                                        f"<b>Remediation Guidance & Configuration:</b><br/>{_clean_str(f_remed).replace(chr(10), '<br/>')}",
                                        code_style
                                    )
                                ]],
                                colWidths=[USABLE_WIDTH]
                            )
                            remed_tbl.setStyle(TableStyle([
                                ("BACKGROUND", (0, 0), (-1, -1), CODE_BG),
                                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#334155")),
                                ("TOPPADDING", (0, 0), (-1, -1), 4),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                            ]))
                            finding_elements.append(remed_tbl)

                        ev_ref = f.get("evidence_reference", {})
                        ev_chain_str = ev_ref.get("evidence_chain")
                        obs_val = ev_ref.get("observed_value")
                        if ev_chain_str or obs_val:
                            ev_row = [
                                Paragraph(
                                    f"<b>Observed on Wire:</b> {_clean_str(obs_val or 'Observed packet anomaly')}<br/>"
                                    f"<b>Evidence Provenance Chain:</b> <font color='#475569'>{_clean_str(ev_chain_str or '')}</font>",
                                    ParagraphStyle("EvChainP", parent=mono_small, fontSize=6.5, leading=8.5, textColor=TEXT_DARK)
                                )
                            ]
                            ev_tbl = Table([ev_row], colWidths=[USABLE_WIDTH])
                            ev_tbl.setStyle(TableStyle([
                                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                                ("TOPPADDING", (0, 0), (-1, -1), 3),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                            ]))
                            finding_elements.append(ev_tbl)

                        finding_elements.append(Spacer(1, 5))
                        story.append(KeepTogether(finding_elements))

                story.append(Spacer(1, 6))

        # ── 5. Packet-Level Evidence Mapping ─────────────────────────────────
        forensic_meta = report.get("forensic_evidence_and_chain_of_custody", {})
        evidence_list = forensic_meta.get("packet_level_evidence_mapping", [])

        if evidence_list:
            story.append(Paragraph("4. PACKET-LEVEL EVIDENCE MAPPING", sec_h1))
            story.append(Paragraph(
                "Verifiable provenance chain mapping each forensic finding to packet numbers, byte offsets, and observed wire values without altering source captures.",
                body_muted
            ))
            story.append(Spacer(1, 4))

            ev_rows = [
                [
                    Paragraph("<b>Finding ID / Rule</b>", body_style),
                    Paragraph("<b>Session Flow</b>", body_style),
                    Paragraph("<b>Pkt / Offset</b>", body_style),
                    Paragraph("<b>Observed Wire Value</b>", body_style),
                    Paragraph("<b>Evidence Chain</b>", body_style),
                ]
            ]
            for ev in evidence_list:
                f_id_disp = str(ev.get("finding_id", ""))[:8]
                rule_disp = str(ev.get("detection_rule", ""))
                ev_rows.append([
                    Paragraph(f"<b>{_clean_str(rule_disp)}</b><br/><font color='#64748B'>#{_clean_str(f_id_disp)}</font>", body_style),
                    Paragraph(_clean_str(ev.get("session_flow", "")), body_style),
                    Paragraph(_clean_str(f"Pkt #{ev.get('packet_number', 0)} (Off {ev.get('byte_offset', 0)})"), body_style),
                    Paragraph(_clean_str(str(ev.get("observed_value", ""))), mono_small),
                    Paragraph(_clean_str(str(ev.get("evidence_chain", ""))), ParagraphStyle("EvChMini", parent=mono_small, fontSize=6, leading=7.5, textColor=TEXT_MUTED)),
                ])

            ev_table = Table(
                ev_rows,
                colWidths=[USABLE_WIDTH * 0.18, USABLE_WIDTH * 0.22, USABLE_WIDTH * 0.15, USABLE_WIDTH * 0.20, USABLE_WIDTH * 0.25],
            )
            ev_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(ev_table)
            story.append(Spacer(1, 10))

        # Build document with custom canvas
        doc.build(story, canvasmaker=NumberedCanvas)
        logger.info("Forensic PDF report generated successfully: %s", output_path)
        return True

    except Exception as exc:
        logger.exception("ReportLab PDF generation failed: %s", exc)
        return False


def to_pdf(report: dict, output_path: str | Path) -> bool:
    """
    Render the report as a PDF file.

    Tries WeasyPrint first; falls back to ReportLab.
    Returns True if PDF was generated successfully, False otherwise.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # ── Try WeasyPrint if installed ─────────────────────────────────────────
    try:
        from weasyprint import HTML as WP_HTML  # type: ignore
        html = to_html(report)
        WP_HTML(string=html, base_url=str(_TEMPLATES_DIR)).write_pdf(str(output_path))
        logger.info("PDF generated with WeasyPrint: %s", output_path)
        return True
    except ImportError:
        logger.debug("WeasyPrint not installed — using ReportLab generator.")
    except Exception as exc:
        logger.warning("WeasyPrint failed (%s) — using ReportLab generator.", exc)

    # ── ReportLab generator ─────────────────────────────────────────────────
    return _generate_reportlab_pdf(report, output_path)

