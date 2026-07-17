"""
rules_db.py — ISHAX EDR Rules Database Manager
================================================
Single source of truth for all Sigma rules.
Stored in rules.db (separate from edr.db / events / alerts).

Visibility model:
  tenant_id = NULL  -> global rule, visible to ALL users
  tenant_id = <id>  -> private rule, visible only to that tenant + admins
  is_admin = True   -> sees everything
"""
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Optional

import yaml as _yaml

_DB_PATH = os.path.join(os.path.dirname(__file__), "rules.db")

_DDL = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS sigma_rules (
    rule_id          TEXT PRIMARY KEY,
    tenant_id        TEXT DEFAULT NULL,
    uploaded_by      TEXT DEFAULT NULL,
    title            TEXT NOT NULL DEFAULT 'Unnamed',
    description      TEXT NOT NULL DEFAULT '',
    author           TEXT NOT NULL DEFAULT '',
    date             TEXT NOT NULL DEFAULT '',
    status           TEXT NOT NULL DEFAULT 'test',
    severity         TEXT NOT NULL DEFAULT 'medium',
    logsource        TEXT NOT NULL DEFAULT '{}',
    mitre_techniques TEXT NOT NULL DEFAULT '[]',
    tags             TEXT NOT NULL DEFAULT '[]',
    rule_references  TEXT NOT NULL DEFAULT '[]',
    falsepositives   TEXT NOT NULL DEFAULT '[]',
    yaml_content     TEXT NOT NULL,
    enabled          INTEGER NOT NULL DEFAULT 1,
    is_custom        INTEGER NOT NULL DEFAULT 0,
    hit_count        INTEGER NOT NULL DEFAULT 0,
    last_fired_at    INTEGER DEFAULT NULL,
    noise_score      REAL NOT NULL DEFAULT 0.0,
    created_at       INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    updated_at       INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
CREATE INDEX IF NOT EXISTS idx_sr_tenant   ON sigma_rules(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sr_enabled  ON sigma_rules(enabled);
CREATE INDEX IF NOT EXISTS idx_sr_severity ON sigma_rules(severity);
CREATE INDEX IF NOT EXISTS idx_sr_custom   ON sigma_rules(is_custom);
CREATE INDEX IF NOT EXISTS idx_sr_hits     ON sigma_rules(hit_count);
"""


def get_rules_db() -> sqlite3.Connection:
    con = sqlite3.connect(_DB_PATH)
    con.row_factory = sqlite3.Row
    con.executescript(_DDL)
    return con


def _parse_yaml_fields(raw: str) -> dict:
    """Parse raw YAML and extract all metadata columns."""
    try:
        parsed = _yaml.safe_load(raw) or {}
    except Exception:
        parsed = {}

    tags_raw = [str(t) for t in (parsed.get("tags") or [])]
    mitre = [
        t.replace("attack.", "").upper()
        for t in tags_raw
        if t.lower().startswith("attack.t")
    ]
    other_tags = [t for t in tags_raw if not t.lower().startswith("attack.t")]

    refs = parsed.get("rule_references") or []
    if isinstance(refs, str):
        refs = [refs]

    fps = parsed.get("falsepositives") or []
    if isinstance(fps, str):
        fps = [fps]

    logsource = parsed.get("logsource") or {}
    level = (parsed.get("level") or "medium").lower()
    severity = {"critical": "critical", "high": "high", "low": "low"}.get(level, "medium")

    return {
        "rule_id":          str(parsed.get("id") or ""),
        "title":            str(parsed.get("title") or "Unnamed"),
        "description":      str(parsed.get("description") or ""),
        "date":             str(parsed.get("date") or ""),
        "severity":         severity,
        "logsource":        json.dumps(logsource),
        "mitre_techniques": json.dumps(mitre),
        "tags":             json.dumps(other_tags),
        "rule_references":       json.dumps(refs),
        "falsepositives":   json.dumps(fps),
    }


def upsert_rule(
    raw_yaml: str,
    is_custom: int = 0,
    tenant_id: Optional[str] = None,
    uploaded_by: Optional[str] = None,
) -> dict:
    """Parse YAML, store all metadata + raw yaml. Raises ValueError on bad input."""
    fields = _parse_yaml_fields(raw_yaml)
    if not fields["rule_id"]:
        raise ValueError("Rule YAML must contain an 'id' field (UUID).")
    if not fields["title"] or fields["title"] == "Unnamed":
        raise ValueError("Rule YAML must contain a 'title' field.")

    now = int(time.time())
    con = get_rules_db()
    try:
        con.execute(
            """
            INSERT INTO sigma_rules
                (rule_id, tenant_id, uploaded_by, title, description, date,
                 severity, logsource, mitre_techniques, tags, rule_references,
                 falsepositives, yaml_content, enabled, is_custom, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?)
            ON CONFLICT(rule_id) DO UPDATE SET
                tenant_id=excluded.tenant_id, uploaded_by=excluded.uploaded_by,
                title=excluded.title, description=excluded.description,
                date=excluded.date,
                severity=excluded.severity,
                logsource=excluded.logsource, mitre_techniques=excluded.mitre_techniques,
                tags=excluded.tags, rule_references=excluded.rule_references,
                falsepositives=excluded.falsepositives, yaml_content=excluded.yaml_content,
                is_custom=excluded.is_custom, updated_at=excluded.updated_at
            """,
            (
                fields["rule_id"], tenant_id, uploaded_by,
                fields["title"], fields["description"],
                fields["date"], fields["severity"],
                fields["logsource"], fields["mitre_techniques"],
                fields["tags"], fields["rule_references"], fields["falsepositives"],
                raw_yaml, is_custom, now, now,
            ),
        )
        con.commit()
    finally:
        con.close()
    return {**fields, "is_custom": is_custom, "tenant_id": tenant_id, "uploaded_by": uploaded_by}


def update_rule_yaml(rule_id: str, raw_yaml: str) -> bool:
    """Replace raw yaml AND re-parse all metadata columns atomically."""
    fields = _parse_yaml_fields(raw_yaml)
    now = int(time.time())
    con = get_rules_db()
    try:
        cur = con.execute(
            """UPDATE sigma_rules SET
                title=?, description=?, date=?, severity=?,
                logsource=?, mitre_techniques=?, tags=?, rule_references=?,
                falsepositives=?, yaml_content=?, updated_at=?
               WHERE rule_id=?""",
            (
                fields["title"], fields["description"],
                fields["date"], fields["severity"],
                fields["logsource"], fields["mitre_techniques"], fields["tags"],
                fields["rule_references"], fields["falsepositives"],
                raw_yaml, now, rule_id,
            ),
        )
        con.commit()
        return cur.rowcount > 0
    finally:
        con.close()


def update_rule_meta(rule_id: str, updates: dict) -> bool:
    """Update editable metadata fields (not yaml_content/detection logic)."""
    allowed = {
        "title", "description", "date", "severity",
        "tags", "mitre_techniques", "rule_references", "falsepositives",
    }
    safe = {k: v for k, v in updates.items() if k in allowed}
    if not safe:
        return False
    for k in ("tags", "mitre_techniques", "rule_references", "falsepositives"):
        if k in safe and isinstance(safe[k], list):
            safe[k] = json.dumps(safe[k])
    safe["updated_at"] = int(time.time())
    cols = ", ".join(f"{k} = ?" for k in safe)
    vals = list(safe.values()) + [rule_id]
    con = get_rules_db()
    try:
        cur = con.execute(f"UPDATE sigma_rules SET {cols} WHERE rule_id = ?", vals)
        con.commit()
        return cur.rowcount > 0
    finally:
        con.close()


def toggle_rule(rule_id: str, enabled: bool) -> bool:
    con = get_rules_db()
    try:
        cur = con.execute(
            "UPDATE sigma_rules SET enabled=?, updated_at=? WHERE rule_id=?",
            (1 if enabled else 0, int(time.time()), rule_id),
        )
        con.commit()
        return cur.rowcount > 0
    finally:
        con.close()


def delete_rule(rule_id: str) -> bool:
    con = get_rules_db()
    try:
        cur = con.execute("DELETE FROM sigma_rules WHERE rule_id=?", (rule_id,))
        con.commit()
        return cur.rowcount > 0
    finally:
        con.close()


def get_rule_yaml(rule_id: str) -> Optional[str]:
    con = get_rules_db()
    try:
        row = con.execute(
            "SELECT yaml_content FROM sigma_rules WHERE rule_id=?", (rule_id,)
        ).fetchone()
        return row["yaml_content"] if row else None
    finally:
        con.close()


def get_rules(tenant_id: Optional[str] = None, is_admin: bool = False) -> list:
    """
    Admin -> all rows (global + every tenant custom).
    User  -> global (tenant_id IS NULL) + own (tenant_id = tenant_id).
    """
    con = get_rules_db()
    try:
        if is_admin:
            rows = con.execute(
                "SELECT * FROM sigma_rules ORDER BY is_custom ASC, title ASC"
            ).fetchall()
        else:
            rows = con.execute(
                """SELECT * FROM sigma_rules
                   WHERE tenant_id IS NULL OR tenant_id = ?
                   ORDER BY is_custom ASC, title ASC""",
                (tenant_id,),
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()


def get_enabled_rules_for_detection() -> list:
    """Return only enabled rules yaml — used by detector to reload SIGMA_RULES."""
    con = get_rules_db()
    try:
        rows = con.execute(
            "SELECT rule_id, yaml_content FROM sigma_rules WHERE enabled=1"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()


def migrate_yamls_to_db(yaml_dir: str) -> int:
    """One-time migration: read all .yml files, insert into DB as global rules."""
    p = Path(yaml_dir)
    if not p.exists():
        print(f"[rules_db] migrate: not found: {yaml_dir}", flush=True)
        return 0
    count = 0
    for f in sorted(p.glob("*.yml")):
        raw = f.read_text(encoding="utf-8")
        is_custom = 1 if (f.name.startswith("custom_") or "enhanced" in f.name) else 0
        try:
            upsert_rule(raw, is_custom=is_custom, tenant_id=None, uploaded_by="system")
            count += 1
        except Exception as exc:
            print(f"[rules_db] migrate skip {f.name}: {exc}", flush=True)
    print(f"[rules_db] Migrated {count} rules from {yaml_dir}", flush=True)
    return count


def record_rule_hit(rule_id: str) -> None:
    """
    Called by detector each time a Sigma rule fires an alert.
    Increments hit_count, updates last_fired_at, recomputes noise_score.
    noise_score = hit_count / max(days_since_created, 1)
    Rules with noise_score > 10.0/day are auto-flagged (high noise).
    """
    now = int(time.time())
    con = get_rules_db()
    try:
        con.execute(
            """
            UPDATE sigma_rules SET
                hit_count    = hit_count + 1,
                last_fired_at = ?,
                noise_score  = CAST(hit_count + 1 AS REAL) /
                               MAX(1, CAST((? - created_at) AS REAL) / 86400.0),
                updated_at   = ?
            WHERE rule_id = ?
            """,
            (now, now, now, rule_id),
        )
        con.commit()
    except Exception as exc:
        print(f"[rules_db] record_rule_hit failed ({rule_id}): {exc}", flush=True)
    finally:
        con.close()


def get_rule_stats() -> list:
    """
    Rule Performance Report:
    Returns all rules ranked by hit_count DESC.
    Includes: rule_id, title, severity, status, hit_count,
              last_fired_at, noise_score, enabled, is_custom, uploaded_by.
    Dead rules = enabled=1 AND hit_count=0.
    High noise = noise_score > 10.0 hits/day.
    """
    con = get_rules_db()
    try:
        rows = con.execute(
            """
            SELECT rule_id, title, severity, hit_count,
                   last_fired_at, noise_score, enabled, is_custom,
                   uploaded_by, tenant_id, created_at
            FROM sigma_rules
            ORDER BY hit_count DESC, title ASC
            """
        ).fetchall()
        result = []
        now = int(time.time())
        for r in rows:
            days_active = max(1, (now - (r["created_at"] or now)) / 86400.0)
            result.append({
                **dict(r),
                "is_dead":       r["enabled"] == 1 and r["hit_count"] == 0,
                "is_high_noise": r["noise_score"] > 10.0,
                "days_active":   round(days_active, 1),
            })
        return result
    finally:
        con.close()


def add_missing_columns() -> None:
    """
    Safe migration: add new columns to existing rules.db that may have been
    created before hit_count/last_fired_at/noise_score were added.
    SQLite does not support IF NOT EXISTS for ALTER TABLE ADD COLUMN,
    so we catch OperationalError silently.
    """
    con = get_rules_db()
    try:
        for col_def in [
            "ALTER TABLE sigma_rules ADD COLUMN hit_count INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE sigma_rules ADD COLUMN last_fired_at INTEGER DEFAULT NULL",
            "ALTER TABLE sigma_rules ADD COLUMN noise_score REAL NOT NULL DEFAULT 0.0",
        ]:
            try:
                con.execute(col_def)
            except Exception:
                pass  # column already exists
        con.commit()
    finally:
        con.close()


