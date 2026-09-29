"""
securemailscope/main.py — CLI entrypoint

Usage:
  python main.py analyze <capture.pcap | report.json> [options]
  python main.py retrain              # retrain ML models on saved scans
  python main.py history <host>       # show grade history
  python main.py dashboard            # launch Streamlit dashboard
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def cmd_analyze(args: argparse.Namespace) -> int:
    from securemailscope.pipeline import PipelineConfig, run

    config = PipelineConfig(
        output_dir=args.output,
        rules_path=args.rules,
        db_path=args.db,
        enable_enrichment=args.enrich,
        enable_ml=not args.no_ml,
        enable_anomaly=not args.no_anomaly,
        generate_html=not args.no_html,
        generate_pdf=not args.no_pdf,
        verbose=args.verbose,
    )

    result = run(args.pcap, config)

    if result.error:
        print(f"\n❌ Error: {result.error}", file=sys.stderr)
        return 1

    print("\n" + "=" * 60)
    print("  SecureMailScope Analysis Complete")
    print("=" * 60)
    print(f"  Sessions analyzed : {result.session_count}")
    print(f"  Total findings    : {result.finding_count}")
    print()

    grade_colors = {"A+": "[A+]", "A": "[A]", "B": "[B]", "C": "[C]", "D": "[D]", "E": "[E]", "F": "[F]"}
    for host in result.report.get("hosts", []):
        grade = host["posture_grade"]
        label = host.get("posture_label", "")
        icon = grade_colors.get(grade, "[ ]")
        lbl_str = f"({label})" if label else ""
        print(f"  {icon} {host['host']:30s} Posture: {grade:2s} {lbl_str:12s} Risk Score: {host['posture_score']}/100")
        if host.get("grade_delta"):
            delta_safe = host['grade_delta'].replace("→", "->")
            print(f"       > Delta: {delta_safe}")
        if host.get("why_this_grade"):
            why = host["why_this_grade"]
            if why.get("summary"):
                print(f"       Why this grade? {why['summary']}")


    print()
    if result.json_path:
        print(f"  JSON : {result.json_path}")
    if result.html_path:
        print(f"  HTML : {result.html_path}")
    if result.pdf_path:
        print(f"  PDF  : {result.pdf_path}")
    print()
    print(f"  Source PCAP SHA-256: {result.report.get('source_pcap_sha256', '')}")
    fe = result.report.get("forensic_evidence_and_chain_of_custody", {})
    if fe:
        print(f"  Analysis ID        : {fe.get('analysis_id', '')}")
        print(f"  Integrity          : {fe.get('integrity_statement', '')}")
        print(f"  Status             : {fe.get('passive_offline_status', '')}")
        print(f"  Evidence Traces    : {len(fe.get('packet_level_evidence_mapping', []))} findings mapped to wire packets")
    print("=" * 60)
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    from securemailscope.storage.database import ScanDatabase
    db_kwargs = {"db_path": args.db} if args.db else {}
    db = ScanDatabase(**db_kwargs)
    history = db.get_grade_history(args.host)
    db.close()
    if not history:
        print(f"No scan history for host: {args.host}")
        return 0
    print(f"\nGrade history for {args.host}:")
    print(f"{'Date':<14} {'Grade':<8} {'Score':<8} {'PCAP'}")
    print("-" * 60)
    for row in history:
        print(f"{row['scanned_at'][:10]:<14} {row['grade']:<8} {row['score']:<8} {row.get('pcap_path', '')}")
    return 0


def cmd_retrain(args: argparse.Namespace) -> int:
    print("Retraining ML models from scan history…")
    print("(Feature: re-reads all stored feature vectors from SQLite and retrains)")
    print("Note: Full retrain pipeline to be implemented in v1.1")
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    import subprocess
    dashboard_path = Path(__file__).parent / "dashboard" / "app.py"
    if not dashboard_path.exists():
        print(f"Dashboard not found at {dashboard_path}", file=sys.stderr)
        return 1
    print(f"Launching dashboard: streamlit run {dashboard_path}")
    subprocess.run(["streamlit", "run", str(dashboard_path)], check=False)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="securemailscope",
        description="SecureMailScope — Passive Email TLS Forensic Tool",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command")

    # analyze
    p_analyze = sub.add_parser("analyze", help="Analyze a PCAP or load/export a JSON report")
    p_analyze.add_argument("pcap", help="Path to .pcap/.pcapng file or .json report file")
    p_analyze.add_argument("-o", "--output", default=".", help="Output directory")
    p_analyze.add_argument("--rules", help="Custom rules.yaml path")
    p_analyze.add_argument("--db", help="Custom SQLite DB path")
    p_analyze.add_argument("--enrich", action="store_true", help="Enable optional enrichment")
    p_analyze.add_argument("--no-ml", action="store_true", help="Skip ML risk scoring")
    p_analyze.add_argument("--no-anomaly", action="store_true", help="Skip anomaly detection")
    p_analyze.add_argument("--no-html", action="store_true", help="Skip HTML report")
    p_analyze.add_argument("--no-pdf", action="store_true", help="Skip PDF report")

    # history
    p_hist = sub.add_parser("history", help="Show grade history for a host")
    p_hist.add_argument("host", help="Host key (ip:port)")
    p_hist.add_argument("--db", help="Custom SQLite DB path")

    # retrain
    sub.add_parser("retrain", help="Retrain ML models from saved scan data")

    # dashboard
    sub.add_parser("dashboard", help="Launch Streamlit dashboard")

    args = parser.parse_args()
    _setup_logging(args.verbose)

    if not args.command:
        parser.print_help()
        return 1

    handlers = {
        "analyze": cmd_analyze,
        "history": cmd_history,
        "retrain": cmd_retrain,
        "dashboard": cmd_dashboard,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
