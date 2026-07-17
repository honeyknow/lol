#!/usr/bin/env python3
"""
Reactive VirusTotal enrichment worker.

Only processes indicators queued from confirmed alerts. It never scans raw
continuous telemetry directly.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
import urllib.error
import urllib.request
from pathlib import Path

DB_PATH = os.getenv("EDR_DB_PATH", str(Path(__file__).parent / "edr.db"))
VT_API_KEY = os.getenv("VT_API_KEY", "")
SPACING_SECONDS = int(os.getenv("VT_SPACING_SECONDS", "15"))
STALE_DAYS = int(os.getenv("VT_CACHE_STALE_DAYS", "30"))


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def vt_url(indicator_type: str, indicator: str) -> str:
    if indicator_type == "sha256":
        return f"https://www.virustotal.com/api/v3/files/{indicator}"
    if indicator_type == "ip":
        return f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
    raise ValueError(f"unsupported indicator_type={indicator_type}")


def fetch_vt(indicator_type: str, indicator: str) -> dict:
    req = urllib.request.Request(vt_url(indicator_type, indicator), headers={"x-apikey": VT_API_KEY})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def verdict_from_vt(payload: dict) -> tuple[str, int]:
    stats = (((payload.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {})
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    score = malicious + suspicious
    if malicious:
        return "malicious", score
    if suspicious:
        return "suspicious", score
    return "clean", score


def mark_error(conn: sqlite3.Connection, row_id: int, message: str):
    conn.execute(
        """
        UPDATE threat_intel_queue
        SET status = CASE WHEN attempts >= 3 THEN 'error' ELSE 'queued' END,
            attempts = attempts + 1,
            next_run_at = ?,
            last_error = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (int(time.time()) + 300, message[:500], int(time.time()), row_id),
    )
    conn.commit()


def process_once(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        """
        SELECT id, indicator, indicator_type
        FROM threat_intel_queue
        WHERE status = 'queued' AND next_run_at <= ?
        ORDER BY created_at ASC
        LIMIT 1
        """,
        (int(time.time()),),
    ).fetchone()
    if not row:
        return False

    if not VT_API_KEY:
        mark_error(conn, row["id"], "VT_API_KEY is not set")
        return True

    conn.execute("UPDATE threat_intel_queue SET status='running', updated_at=? WHERE id=?", (int(time.time()), row["id"]))
    conn.commit()

    try:
        payload = fetch_vt(row["indicator_type"], row["indicator"])
        verdict, score = verdict_from_vt(payload)
        now = int(time.time())
        conn.execute(
            """
            INSERT INTO threat_intel_cache(indicator, indicator_type, provider, verdict, score, raw_json, checked_at, stale_after)
            VALUES (?, ?, 'virustotal', ?, ?, ?, ?, ?)
            ON CONFLICT(indicator) DO UPDATE SET
                verdict=excluded.verdict,
                score=excluded.score,
                raw_json=excluded.raw_json,
                checked_at=excluded.checked_at,
                stale_after=excluded.stale_after
            """,
            (
                row["indicator"], row["indicator_type"], verdict, score,
                json.dumps(payload, separators=(",", ":")), now, now + STALE_DAYS * 86400,
            ),
        )
        conn.execute("UPDATE threat_intel_queue SET status='done', updated_at=? WHERE id=?", (now, row["id"]))
        conn.commit()
        print(f"[VT] {row['indicator_type']} {row['indicator']} -> {verdict} score={score}", flush=True)
    except urllib.error.HTTPError as exc:
        retry = 900 if exc.code == 429 else 300
        conn.execute(
            """
            UPDATE threat_intel_queue
            SET status='queued', attempts=attempts+1, next_run_at=?, last_error=?, updated_at=?
            WHERE id=?
            """,
            (int(time.time()) + retry, f"HTTP {exc.code}", int(time.time()), row["id"]),
        )
        conn.commit()
    except Exception as exc:
        mark_error(conn, row["id"], str(exc))
    return True


def main():
    print(f"[VT] worker started db={DB_PATH} spacing={SPACING_SECONDS}s", flush=True)
    with connect() as conn:
        while True:
            did_work = process_once(conn)
            time.sleep(SPACING_SECONDS if did_work else 5)


if __name__ == "__main__":
    main()
