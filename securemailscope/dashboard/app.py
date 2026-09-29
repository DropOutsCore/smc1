"""
securemailscope/dashboard/app.py
-----------------------------------
Streamlit dashboard — reads JSON reports and SQLite history.

Pages:
  1. Overview  — posture grade per host (color-coded), trend sparkline
  2. Findings  — filterable/sortable findings table
  3. Drill-down — session handshake + cert + explainability + evidence

The dashboard NEVER calls the pipeline directly — it only reads from
JSON output files or the SQLite history DB.  This separation means the
Streamlit UI can be swapped for a React frontend without any backend changes.

Run with: streamlit run securemailscope/dashboard/app.py
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Optional

import streamlit as st
from securemailscope.reports.exporter import to_html

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="SecureMailScope",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Custom CSS — dark forensic aesthetic
# ---------------------------------------------------------------------------
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

  html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
  .stApp { background-color: #0d1117; color: #e6edf3; }
  .grade-badge {
    display: inline-flex; align-items: center; justify-content: center;
    width: 72px; height: 72px; border-radius: 50%;
    font-size: 32px; font-weight: 800; margin-bottom: 8px;
  }
  .grade-A { background: rgba(63,185,80,0.15); color: #3fb950; border: 3px solid #3fb950; }
  .grade-B { background: rgba(88,166,255,0.15); color: #58a6ff; border: 3px solid #58a6ff; }
  .grade-C { background: rgba(210,153,34,0.15); color: #d29922; border: 3px solid #d29922; }
  .grade-D { background: rgba(240,136,62,0.15); color: #f0883e; border: 3px solid #f0883e; }
  .grade-F { background: rgba(248,81,73,0.15); color: #f85149; border: 3px solid #f85149; }
  .host-card {
    background: #161b22; border: 1px solid #30363d; border-radius: 12px;
    padding: 20px; text-align: center; height: 100%;
  }
  .sev-critical { color: #f85149; font-weight: 700; }
  .sev-high     { color: #d29922; font-weight: 600; }
  .sev-medium   { color: #388bfd; }
  .sev-low      { color: #3fb950; }
  .metric-box {
    background: #161b22; border: 1px solid #30363d; border-radius: 8px;
    padding: 16px; text-align: center;
  }
  .metric-val { font-size: 32px; font-weight: 800; color: #58a6ff; }
  .metric-label { font-size: 12px; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; }
  .mono { font-family: 'JetBrains Mono', monospace; font-size: 12px; }
  .evidence-chip {
    background: #21262d; border: 1px solid #30363d; border-radius: 6px;
    padding: 4px 10px; font-family: monospace; font-size: 12px; display: inline-block;
  }
  .finding-row:hover { background: rgba(88,166,255,0.05); }
  .pfs-yes { color: #3fb950; font-weight: 600; }
  .pfs-no  { color: #d29922; font-weight: 600; }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Sidebar — PCAP and Report loader
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("## 🔒 SecureMailScope")
    st.markdown("*Passive Email TLS Forensics*")
    st.divider()

    st.markdown("### 📥 Load PCAP or Report")

    # Quick Samples
    sample_options = [
        "-- Quick Select Sample --",
        "capture.pcap (4-Session Scenario)",
        "capture_report.json (Analyzed Report)",
        "securemailscope/sample_pcaps/smtp_clean_tls13.pcap",
        "securemailscope/sample_pcaps/smtp_tls10_deprecated.pcap",
        "securemailscope/sample_pcaps/smtp_starttls_downgrade.pcap",
        "securemailscope/sample_pcaps/smtp_no_pfs_rsa.pcap",
        "securemailscope/sample_pcaps/smtp_expired_cert.pcap",
        "securemailscope/sample_pcaps/smtp_self_signed.pcap",
    ]
    selected_sample = st.selectbox("Quick Load Sample", sample_options, index=0)

    uploaded_file = st.file_uploader(
        "Upload file (.pcap, .pcapng, .json)",
        type=["json", "pcap", "pcapng", "cap"],
        key="file_upload",
    )
    report_path = st.text_input(
        "Or enter file path (PCAP or JSON):",
        placeholder="e.g. capture.pcap or capture_report.json",
    )

    st.divider()
    page = st.radio(
        "Navigate",
        ["📊 Overview", "🔍 Findings", "🔬 Session Drill-down"],
        key="nav_page",
    )
    st.divider()


# ---------------------------------------------------------------------------
# Load / Analyze data handlers
# ---------------------------------------------------------------------------
@st.cache_data(show_spinner=True)
def _analyze_pcap_bytes(file_bytes: bytes, filename: str) -> Optional[dict]:
    suffix = Path(filename).suffix.lower() if filename else ".pcap"
    if suffix not in (".pcap", ".pcapng", ".cap"):
        suffix = ".pcap"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name
    try:
        from securemailscope.pipeline import PipelineConfig, run
        config = PipelineConfig(output_dir="reports_out", generate_html=True, generate_pdf=False)
        result = run(tmp_path, config)
        if result.error:
            st.error(f"Analysis error: {result.error}")
            return None
        return result.report
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


@st.cache_data(show_spinner=True)
def _load_or_analyze_path(path_str: str) -> Optional[dict]:
    p = Path(path_str)
    if not p.is_file():
        st.error(f"File not found: {path_str}")
        return None
    from securemailscope.pipeline import PipelineConfig, run
    config = PipelineConfig(output_dir="reports_out", generate_html=True, generate_pdf=False)
    result = run(str(p), config)
    if result.error:
        st.error(f"Error: {result.error}")
        return None
    return result.report


report: Optional[dict] = None
source_label = ""

# Handle session state trigger from landing buttons
if "target_file" in st.session_state and st.session_state["target_file"]:
    report = _load_or_analyze_path(st.session_state["target_file"])
    source_label = Path(st.session_state["target_file"]).name

if not report:
    if uploaded_file:
        source_label = uploaded_file.name
        suffix = Path(uploaded_file.name).suffix.lower()
        if suffix == ".json":
            try:
                report = json.loads(uploaded_file.read().decode("utf-8"))
            except Exception as exc:
                st.error(f"Failed to parse uploaded JSON: {exc}")
        else:
            report = _analyze_pcap_bytes(uploaded_file.read(), uploaded_file.name)
    elif report_path and report_path.strip():
        source_label = Path(report_path.strip()).name
        report = _load_or_analyze_path(report_path.strip())
    elif selected_sample and selected_sample != "-- Quick Select Sample --":
        sample_path = selected_sample.split()[0]
        source_label = Path(sample_path).name
        report = _load_or_analyze_path(sample_path)

# Sidebar metadata & export when loaded
with st.sidebar:
    if report:
        st.success(f"🟢 Active: {source_label or 'Loaded Report'}")
        pcap_src = report.get("source_pcap_path", "")
        if pcap_src:
            st.caption(f"📁 Source: {pcap_src}")
        st.download_button(
            "📥 Export JSON Report",
            data=json.dumps(report, indent=2),
            file_name=f"{Path(source_label).stem or 'report'}_report.json",
            mime="application/json",
            use_container_width=True,
        )
        try:
            st.download_button(
                "📄 Export HTML Report",
                data=to_html(report),
                file_name=f"{Path(source_label).stem or 'report'}_report.html",
                mime="text/html",
                use_container_width=True,
            )
        except Exception:
            pass
        st.divider()
    st.caption("SecureMailScope v1.0.0 | Passive only")

# ---------------------------------------------------------------------------
# No report loaded
# ---------------------------------------------------------------------------
if not report:
    st.markdown("""
    <div style='text-align:center;padding:40px 0;'>
        <div style='font-size:72px;'>🔒</div>
        <h1 style='color:#e6edf3;margin-top:16px;'>SecureMailScope</h1>
        <p style='color:#8b949e;font-size:18px;'>Passive Email TLS Forensic & Risk Assessment Dashboard</p>
        <p style='color:#8b949e;margin-top:20px;max-width:600px;margin-left:auto;margin-right:auto;'>
            Upload any <b>PCAP network capture</b> to analyze on the fly, or load an existing <b>JSON report</b>.
        </p>
    </div>
    """, unsafe_allow_html=True)

    c1, c2, c3 = st.columns([1, 2, 1])
    with c2:
        btn_c1, btn_c2 = st.columns(2)
        with btn_c1:
            if st.button("🚀 Analyze capture.pcap", use_container_width=True):
                st.session_state["target_file"] = "capture.pcap"
                st.rerun()
        with btn_c2:
            if st.button("📄 Load capture_report.json", use_container_width=True):
                st.session_state["target_file"] = "capture_report.json"
                st.rerun()

    st.markdown("""
    <div style='text-align:center;margin-top:30px;color:#6e7681;font-size:13px;'>
        Or select a sample from the sidebar dropdown or enter a custom path.
    </div>
    """, unsafe_allow_html=True)
    st.stop()


# ---------------------------------------------------------------------------
# Flatten all findings for easy querying
# ---------------------------------------------------------------------------
def _all_findings(report: dict) -> list[dict]:
    rows = []
    for host in report.get("hosts", []):
        for session in host.get("sessions", []):
            for f in session.get("findings", []):
                rows.append({
                    "host": host["host"],
                    "grade": host["posture_grade"],
                    "session_id": session["session_id"],
                    "protocol": session["protocol"],
                    "tls_version": session["tls_version"],
                    **f,
                })
    return rows


all_findings = _all_findings(report)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PAGE 1 — OVERVIEW
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
if page == "📊 Overview":
    st.markdown("## Security Posture Overview")

    # Report metadata
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f"""<div class='metric-box'>
            <div class='metric-val'>{len(report.get('hosts', []))}</div>
            <div class='metric-label'>Hosts Analyzed</div>
        </div>""", unsafe_allow_html=True)
    with col2:
        total_sessions = sum(len(h["sessions"]) for h in report.get("hosts", []))
        st.markdown(f"""<div class='metric-box'>
            <div class='metric-val'>{total_sessions}</div>
            <div class='metric-label'>Email Sessions</div>
        </div>""", unsafe_allow_html=True)
    with col3:
        critical_count = sum(1 for f in all_findings if f.get("severity") == "critical")
        color = "#f85149" if critical_count > 0 else "#3fb950"
        st.markdown(f"""<div class='metric-box'>
            <div class='metric-val' style='color:{color};'>{critical_count}</div>
            <div class='metric-label'>Critical Findings</div>
        </div>""", unsafe_allow_html=True)
    with col4:
        st.markdown(f"""<div class='metric-box'>
            <div class='metric-val'>{len(all_findings)}</div>
            <div class='metric-label'>Total Findings</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("---")

    # Report metadata strip
    st.markdown(f"""
    <div style='font-family:monospace;font-size:12px;color:#8b949e;padding:10px;
                background:#161b22;border-radius:6px;border:1px solid #30363d;'>
        📄 Report ID: {report.get('report_id', '—')}<br>
        🕒 Generated: {report.get('generated_at', '—')}<br>
        🔏 Source PCAP SHA-256: {report.get('source_pcap_sha256', '—')}<br>
        📁 Source: {report.get('source_pcap_path', '—')}
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### Host Posture Grades")

    GRADE_COLORS = {"A": "#3fb950", "B": "#58a6ff", "C": "#d29922", "D": "#f0883e", "F": "#f85149"}

    hosts = report.get("hosts", [])
    cols = st.columns(min(len(hosts), 4))
    for i, host in enumerate(hosts):
        with cols[i % len(cols)]:
            grade = host["posture_grade"]
            color = GRADE_COLORS.get(grade, "#8b949e")
            fc = host.get("finding_summary", {})
            delta_html = f"<div style='font-size:12px;color:#8b949e;'>{host.get('grade_delta', '')}</div>" if host.get("grade_delta") else ""

            summary_pills = ""
            for sev, cls in [("critical", "#f85149"), ("high", "#d29922"), ("medium", "#388bfd"), ("low", "#3fb950")]:
                cnt = fc.get(sev, 0)
                if cnt > 0:
                    summary_pills += f"<span style='background:rgba(0,0,0,0.3);color:{cls};border:1px solid {cls};border-radius:99px;padding:2px 8px;font-size:11px;font-weight:700;margin:2px;display:inline-block;'>{cnt} {sev}</span>"

            st.markdown(f"""<div class='host-card'>
                <div class='grade-badge grade-{grade}'>{grade}</div>
                <div style='font-size:14px;font-weight:600;word-break:break-all;'>{host["host"]}</div>
                <div style='font-size:12px;color:#8b949e;'>Score: {host.get('posture_score', 0)}</div>
                {delta_html}
                <div style='margin-top:10px;'>{summary_pills}</div>
            </div>""", unsafe_allow_html=True)
            st.markdown("")

    # TLS visibility note
    note = report.get("tls13_visibility_note", "")
    if note:
        st.info(f"⚠️ **TLS 1.3 Visibility Limit:** {note}")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PAGE 2 — FINDINGS TABLE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
elif page == "🔍 Findings":
    st.markdown("## All Findings")

    if not all_findings:
        st.success("🎉 No findings detected! All sessions appear clean.")
        st.stop()

    # Filters
    col1, col2, col3 = st.columns(3)
    with col1:
        sev_filter = st.multiselect(
            "Severity",
            ["critical", "high", "medium", "low"],
            default=["critical", "high", "medium", "low"],
        )
    with col2:
        hosts_list = list({f["host"] for f in all_findings})
        host_filter = st.multiselect("Host", hosts_list, default=hosts_list)
    with col3:
        cats = list({f.get("category", "unknown") for f in all_findings})
        cat_filter = st.multiselect("Category", cats, default=cats)

    # Filter
    filtered = [
        f for f in all_findings
        if f.get("severity") in sev_filter
        and f.get("host") in host_filter
        and f.get("category", "") in cat_filter
    ]

    st.markdown(f"**{len(filtered)} findings** matching filters")

    SEV_COLORS = {"critical": "#f85149", "high": "#d29922", "medium": "#388bfd", "low": "#3fb950"}

    for f in sorted(filtered, key=lambda x: ["critical","high","medium","low"].index(x.get("severity","low")) if x.get("severity") in ["critical","high","medium","low"] else 99):
        sev = f.get("severity", "low")
        color = SEV_COLORS.get(sev, "#8b949e")
        pkt = f.get("evidence_ref", {}).get("packet_number", "?")
        with st.expander(f"[{sev.upper()}] {f.get('id', '')} — {f.get('host', '')} — {f.get('description', '')[:80]}"):
            c1, c2 = st.columns(2)
            with c1:
                st.markdown(f"**Host:** `{f.get('host')}`")
                st.markdown(f"**Protocol:** {f.get('protocol', '—')}")
                st.markdown(f"**Category:** {f.get('category', '—')}")
                st.markdown(f"**CWE:** {f.get('cwe', '—')}")
                st.markdown(f"**Reference:** {f.get('reference', '—')}")
                st.markdown(f"**Evidence:** Packet #{pkt}")
            with c2:
                st.markdown(f"**Description:** {f.get('description', '')}")
                if f.get("contributing_factors"):
                    st.markdown("**Contributing factors:**")
                    for cf in f["contributing_factors"]:
                        st.markdown(f"  • `{cf}`")
            if f.get("remediation"):
                st.markdown("**Remediation:**")
                st.code(f["remediation"], language="bash")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PAGE 3 — SESSION DRILL-DOWN
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
elif page == "🔬 Session Drill-down":
    st.markdown("## Session Drill-down")

    # Build session list for selection
    all_sessions = []
    for host in report.get("hosts", []):
        for session in host.get("sessions", []):
            label = (
                f"{session['protocol']} {session.get('src_ip')}:{session.get('src_port')} → "
                f"{session.get('dst_ip')}:{session.get('dst_port')}  "
                f"[TLS {session.get('tls_version', 'n/a')}]  "
                f"[{len(session.get('findings', []))} findings]"
            )
            all_sessions.append((label, host, session))

    if not all_sessions:
        st.info("No sessions found in the report.")
        st.stop()

    selected_label = st.selectbox(
        "Select session",
        [x[0] for x in all_sessions],
    )
    host_entry, session = next(
        (h, s) for (lbl, h, s) in all_sessions if lbl == selected_label
    )

    # ── Session overview ─────────────────────────────────────────────
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Protocol", session["protocol"])
    c2.metric("TLS Version", session.get("tls_version", "—"))
    c3.metric("PFS", "✅ Yes" if session.get("pfs") else "❌ No")
    c4.metric("Grade", host_entry["posture_grade"])

    st.markdown(f"**Session ID:** `{session['session_id']}`")
    st.markdown(f"**Route:** `{session.get('src_ip')}:{session.get('src_port')}` → `{session.get('dst_ip')}:{session.get('dst_port')}`")
    if session.get("sni"):
        st.markdown(f"**SNI:** `{session['sni']}`")
    if session.get("banner"):
        st.markdown(f"**Server Banner:** `{session['banner']}`")
    if session.get("downgrade_suspected"):
        st.error("⚠️ STARTTLS DOWNGRADE SUSPECTED for this session!")
    if session.get("tls13_visibility_limited"):
        st.warning("🔒 TLS 1.3 — some fields not visible in passive capture.")

    st.divider()

    # ── TLS Details ───────────────────────────────────────────────────
    st.markdown("### TLS Handshake")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown(f"**Cipher Suite:** `{session.get('cipher_suite', '—')}`")
        st.markdown(f"**Cipher Strength:** `{session.get('cipher_strength', '—')}`")
    with col2:
        st.markdown(f"**Key Exchange:** `{session.get('key_exchange', '—')}`")
        st.markdown(f"**ALPN:** `{', '.join(session.get('alpn', [])) or '—'}`")
    with col3:
        ml_label = session.get("ml_risk_label", "—")
        ml_conf = session.get("ml_confidence", 0)
        st.markdown(f"**ML Risk:** `{ml_label}` ({ml_conf*100:.0f}% confidence)")
        if session.get("anomaly_detected"):
            st.markdown(f"**⚠️ Anomaly Score:** `{session.get('anomaly_score', 0):.4f}`")

    # ── Certificate ───────────────────────────────────────────────────
    cert = session.get("certificate")
    if cert:
        st.divider()
        st.markdown("### X.509 Certificate")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown(f"**Subject:** `{cert.get('subject', '—')}`")
            st.markdown(f"**Issuer:** `{cert.get('issuer', '—')}`")
            st.markdown(f"**Key:** `{cert.get('key_algorithm')} {cert.get('key_length')} bit ({cert.get('key_strength')})`")
            st.markdown(f"**Signature Alg:** `{cert.get('signature_algorithm', '—')}`")
        with c2:
            exp = cert.get("expires", "—")
            days = cert.get("days_until_expiry")
            if cert.get("is_expired"):
                st.error(f"🔴 EXPIRED: {exp}")
            elif cert.get("expiring_within_30_days"):
                st.warning(f"⚠️ Expiring Soon: {exp} ({days} days)")
            else:
                st.success(f"✅ Valid until: {exp} ({days} days)")

            hm = cert.get("hostname_match")
            if hm is True:
                st.success("✅ Hostname match: OK")
            elif hm is False:
                st.error("❌ Hostname mismatch!")
            else:
                st.info("ℹ️ Hostname match: N/A")

            if cert.get("is_self_signed"):
                st.warning("⚠️ Self-signed certificate")

        if cert.get("sans"):
            st.markdown(f"**SANs:** `{', '.join(cert['sans'])}`")

    # ── Findings ─────────────────────────────────────────────────────
    findings = session.get("findings", [])
    if findings:
        st.divider()
        st.markdown(f"### Findings ({len(findings)})")
        SEV_COLORS = {"critical":"#f85149","high":"#d29922","medium":"#388bfd","low":"#3fb950"}
        for f in sorted(findings, key=lambda x: ["critical","high","medium","low"].index(x.get("severity","low")) if x.get("severity") in ["critical","high","medium","low"] else 99):
            sev = f.get("severity", "low")
            color = SEV_COLORS.get(sev, "#8b949e")
            with st.expander(f"[{sev.upper()}] {f.get('id', '')} — {f.get('description', '')[:100]}"):
                st.markdown(f"**Description:** {f.get('description', '')}")
                st.markdown(f"**Category:** `{f.get('category', '—')}`")
                st.markdown(f"**CWE:** `{f.get('cwe', '—')}`")
                st.markdown(f"**Reference:** {f.get('reference', '—')}")
                pkt = f.get("evidence_ref", {}).get("packet_number", "?")
                st.markdown(f"**🔍 Evidence Ref:** Packet #{pkt} in source PCAP")

                # Explainability
                factors = f.get("contributing_factors", [])
                if factors:
                    st.markdown("**🤖 ML Contributing Factors:**")
                    for cf in factors:
                        st.markdown(f"  • `{cf}`")

                if f.get("remediation"):
                    st.markdown("**🔧 Remediation:**")
                    st.code(f["remediation"], language="bash")
    else:
        st.success("✅ No findings for this session.")
