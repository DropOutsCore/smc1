"""
securemailscope/storage/database.py
--------------------------------------
SQLite-backed scan history for posture trend tracking.

Schema
------
scans          — one row per analysis run
host_grades    — per-host grade per scan
findings       — individual findings per scan (for historical querying)

Used by the scoring module to retrieve prior grades and compute deltas.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = Path.home() / ".securemailscope" / "history.db"


class ScanDatabase:
    """Thin SQLite wrapper for scan history persistence."""

    def __init__(self, db_path: str | Path = _DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None
        self._connect()
        self._create_schema()

    def _connect(self) -> None:
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

    def _create_schema(self) -> None:
        assert self._conn is not None
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id     TEXT PRIMARY KEY,
                pcap_path   TEXT NOT NULL,
                pcap_sha256 TEXT NOT NULL,
                scanned_at  TEXT NOT NULL,
                packet_count INTEGER,
                session_count INTEGER
            );

            CREATE TABLE IF NOT EXISTS host_grades (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     TEXT NOT NULL REFERENCES scans(scan_id),
                host        TEXT NOT NULL,
                grade       TEXT NOT NULL,
                score       INTEGER NOT NULL,
                finding_counts TEXT,  -- JSON
                UNIQUE(scan_id, host)
            );

            CREATE TABLE IF NOT EXISTS findings (
                finding_id  TEXT PRIMARY KEY,
                scan_id     TEXT NOT NULL REFERENCES scans(scan_id),
                session_id  TEXT NOT NULL,
                host        TEXT NOT NULL,
                rule_id     TEXT NOT NULL,
                category    TEXT NOT NULL,
                severity    TEXT NOT NULL,
                description TEXT,
                evidence_ref TEXT,  -- JSON
                created_at  TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_host_grades_host ON host_grades(host);
            CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(host);
        """)
        self._conn.commit()

    def save_scan(
        self,
        scan_id: str,
        pcap_path: str,
        pcap_sha256: str,
        packet_count: int,
        session_count: int,
    ) -> None:
        assert self._conn is not None
        self._conn.execute(
            """INSERT OR IGNORE INTO scans
               (scan_id, pcap_path, pcap_sha256, scanned_at, packet_count, session_count)
               VALUES (?,?,?,?,?,?)""",
            (
                scan_id, pcap_path, pcap_sha256,
                datetime.now(timezone.utc).isoformat(),
                packet_count, session_count,
            ),
        )
        self._conn.commit()

    def save_host_grade(
        self,
        scan_id: str,
        host: str,
        grade: str,
        score: int,
        finding_counts: dict,
    ) -> None:
        assert self._conn is not None
        self._conn.execute(
            """INSERT OR REPLACE INTO host_grades
               (scan_id, host, grade, score, finding_counts)
               VALUES (?,?,?,?,?)""",
            (scan_id, host, grade, score, json.dumps(finding_counts)),
        )
        self._conn.commit()

    def get_previous_grade(self, host: str) -> Optional[tuple[str, str]]:
        """
        Retrieve the most recent (grade, scan_date) for a host.

        Returns None if no prior scan exists.
        """
        assert self._conn is not None
        row = self._conn.execute(
            """SELECT hg.grade, s.scanned_at
               FROM host_grades hg
               JOIN scans s ON s.scan_id = hg.scan_id
               WHERE hg.host = ?
               ORDER BY s.scanned_at DESC
               LIMIT 1""",
            (host,),
        ).fetchone()
        if row:
            return row["grade"], row["scanned_at"][:10]  # date only
        return None

    def save_findings(self, scan_id: str, findings: list) -> None:
        """Persist a list of Finding objects."""
        assert self._conn is not None
        now = datetime.now(timezone.utc).isoformat()
        self._conn.executemany(
            """INSERT OR IGNORE INTO findings
               (finding_id, scan_id, session_id, host, rule_id, category, severity,
                description, evidence_ref, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            [
                (
                    f.finding_id, scan_id, f.session_id, f.host,
                    f.id, f.category, f.severity,
                    f.description, json.dumps(f.evidence_ref), now,
                )
                for f in findings
            ],
        )
        self._conn.commit()

    def get_grade_history(self, host: str, limit: int = 10) -> list[dict]:
        """Return grade history for a host (newest first)."""
        assert self._conn is not None
        rows = self._conn.execute(
            """SELECT hg.grade, hg.score, s.scanned_at, s.pcap_path
               FROM host_grades hg
               JOIN scans s ON s.scan_id = hg.scan_id
               WHERE hg.host = ?
               ORDER BY s.scanned_at DESC
               LIMIT ?""",
            (host, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None
