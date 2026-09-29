"""
securemailscope/enrichment/__init__.py
---------------------------------------
Optional enrichment modules. All are off by default.

PASSIVE NOTE: These modules do DNS/HTTP lookups against public
READ-ONLY services (crt.sh, Shodan, NVD). They are NOT active
probing of the mail servers found in the PCAP. They must never
be called from the core pipeline unless explicitly enabled.

Each module must:
  1. Return gracefully (no exception propagation) if unavailable
  2. Require explicit opt-in (enable_enrichment=True in config)
  3. Work without API keys (with reduced functionality)
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def run_enrichment(report: dict, session_results: list) -> None:
    """
    Run all enabled enrichment modules.

    This function must never raise — all failures are logged and skipped.
    """
    try:
        from securemailscope.enrichment.crtsh import enrich_crtsh
        enrich_crtsh(report)
    except Exception as exc:
        logger.debug("crt.sh enrichment skipped: %s", exc)
