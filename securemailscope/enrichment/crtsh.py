"""
securemailscope/enrichment/crtsh.py
--------------------------------------
Optional: Certificate Transparency lookup via crt.sh API.

PASSIVE NOTE: This is a READ-ONLY HTTP lookup against the public
crt.sh certificate transparency log search service. It does NOT
connect to any mail server found in the PCAP.

Feature-flagged: only called when enable_enrichment=True.
Fails silently if the network is unavailable.
"""

from __future__ import annotations

import logging
import urllib.request
import urllib.error
import json
from typing import Optional

logger = logging.getLogger(__name__)

_CRTSH_BASE = "https://crt.sh/?q={domain}&output=json"
_TIMEOUT = 5


def lookup_crtsh(domain: str) -> Optional[list[dict]]:
    """
    Query crt.sh for certificate transparency records for a domain.

    Returns None on any error (network unavailable, timeout, etc.)
    """
    try:
        url = _CRTSH_BASE.format(domain=domain)
        req = urllib.request.Request(url, headers={"User-Agent": "SecureMailScope/1.0"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        logger.debug("crt.sh found %d records for %s", len(data), domain)
        return data[:10]  # limit to first 10
    except Exception as exc:
        logger.debug("crt.sh lookup failed for %s: %s", domain, exc)
        return None


def enrich_crtsh(report: dict) -> None:
    """Add crt.sh data to the report (non-blocking, best-effort)."""
    for host_entry in report.get("hosts", []):
        for session in host_entry.get("sessions", []):
            sni = session.get("sni")
            if not sni:
                continue
            records = lookup_crtsh(sni)
            if records is not None:
                session["crtsh_ct_records"] = len(records)
                session["crtsh_enriched"] = True
