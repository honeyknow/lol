import datetime
import json
import os
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import psutil
from typing import Any, Dict, List, Optional
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

import httpx
from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

PHASE2_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "pipeline"))
sys.path.append(PHASE2_DIR)

try:
    from detector import load_sigma_rules, SIGMA_RULES
    from rules_db import add_missing_columns
    add_missing_columns()   # safe no-op if columns already exist
    load_sigma_rules()      # reads from rules.db, not files
except ImportError:
    SIGMA_RULES = []

DB_PATH = os.path.join(PHASE2_DIR, "edr.db")

app = FastAPI(title="ISHA-X EDR Dashboard API")

# ---------------------------------------------------------------------------
# Session middleware (for Google OAuth cookie-based auth)
# ---------------------------------------------------------------------------
_SESSION_SECRET = os.environ.get("SESSION_SECRET", secrets.token_hex(32))
app.add_middleware(SessionMiddleware, secret_key=_SESSION_SECRET, https_only=False)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.environ.get("FRONTEND_ORIGIN", "*")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Deploy config
# ---------------------------------------------------------------------------
SERVER_HOST   = os.environ.get("SERVER_HOST", "agents.weknows.me")
NSIS_PATH     = os.environ.get("NSIS_PATH", "makensis")  # native on Linux, no Wine needed
ENDPOINT_SRC  = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "endpoint"))
WAZUH_API_BASE = os.environ.get("WAZUH_API_BASE", "https://localhost:55000")
WAZUH_API_USER = os.environ.get("WAZUH_API_USER", "wazuh")
WAZUH_API_PASS = os.environ.get("WAZUH_API_PASS", "wazuh")

# Rate-limit: one download per user per 10 seconds (NSIS compiles in ~2-3s)
_download_cooldown: dict = {}


def utc_now() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def utc_from_epoch(epoch: Optional[int]) -> Optional[str]:
    if epoch is None:
        return None
    return datetime.datetime.utcfromtimestamp(int(epoch)).replace(microsecond=0).isoformat() + "Z"


def get_db():
    """Legacy single-tenant fallback — only used if TenantManager fails to init."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    ensure_db_migrations(conn)
    return conn



# ---------------------------------------------------------------------------
# Multi-Tenant routing — lazy singleton
# ---------------------------------------------------------------------------
_saas_manager = None


def _get_saas_manager():
    global _saas_manager
    if _saas_manager is None:
        try:
            from multi_tenant_manager import get_manager
            _saas_manager = get_manager()
        except Exception as exc:
            print(f"[WARN] TenantManager init failed (falling back to single-tenant): {exc}", flush=True)
    return _saas_manager


# Super-admin is hardcoded and can never be locked out
ADMIN_EMAIL = "info.honeyknows@gmail.com"
ADMIN_EMAILS = [ADMIN_EMAIL]   # keep as list for compat


def _is_allowed(email: str) -> bool:
    """
    Check if email is permitted to login.
    1. Super-admin is always allowed (no DB needed).
    2. Otherwise check master.db allowed_users table (live, no restart needed).
    3. Fallback: check ADMIN_EMAILS env var (legacy compat).
    """
    if email == ADMIN_EMAIL:
        return True
    mgr = _get_saas_manager()
    if mgr:
        return mgr.is_email_allowed(email)
    # Fallback if TenantManager not running (single-tenant lab mode)
    env_list = list(filter(None, os.environ.get("ADMIN_EMAILS", "").split(",")))
    return email in [e.strip().lower() for e in env_list]


# ---------------------------------------------------------------------------
# Auth routes (Custom Login)
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    email: str
    password: str

@app.post("/auth/login")
async def auth_login(req: LoginRequest, request: Request):
    """Verify email and password."""
    email = req.email.strip().lower()
    if not email:
        raise HTTPException(400, "Email is required.")
        
    admin_password = os.environ.get("ADMIN_PASSWORD", "")
    
    if email == ADMIN_EMAIL:
        if not admin_password or req.password != admin_password:
            raise HTTPException(401, "Invalid email or password.")
    else:
        mgr = _get_saas_manager()
        if not mgr or not mgr.verify_user_password(email, req.password):
            raise HTTPException(401, "Invalid email or password.")

    request.session["user_email"] = email
    role = "admin" if email == ADMIN_EMAIL else "user"
    return {"authenticated": True, "email": email, "role": role}

@app.post("/auth/logout")
async def auth_logout(request: Request):
    request.session.clear()
    return {"authenticated": False}

@app.get("/auth/me")
def auth_me(request: Request):
    """Frontend polls this to check if logged in."""
    email = request.session.get("user_email")
    if not email:
        return {"authenticated": False}
    role = "admin" if email == ADMIN_EMAIL else "user"
    return {"authenticated": True, "email": email, "role": role}

@app.delete("/delete-my-data")
async def delete_my_data(request: Request):
    """Users can permanently delete their own account and all data."""
    user = get_current_user(request)
    email = user.get("email", "")
    tenant = user.get("tenant") or {}
    tenant_id = tenant.get("id")
    mgr = _get_saas_manager()
    if not mgr:
        raise HTTPException(503, "Service unavailable.")
    if not tenant_id:
        # Try fetching tenant directly in case get_current_user didn't populate it
        t = mgr.get_tenant_by_email(email)
        if t:
            tenant_id = t.get("id")
    if not tenant_id:
        raise HTTPException(404, "Tenant not found.")

    # Revoke Wazuh agents — best-effort, don't fail if Wazuh is offline
    try:
        agents = mgr.get_agents_for_tenant(tenant_id)
        for ag in agents:
            try:
                await _wazuh_delete_agent(ag["agent_id"])
            except Exception:
                pass
    except Exception:
        pass

    # Purge from master.db + delete .db file
    mgr.purge_tenant(tenant_id)

    # Also remove from allowed_users whitelist so they can't log back in
    try:
        mgr.remove_allowed_user(email)
    except Exception:
        pass

    # Clear session
    request.session.clear()
    return {"status": "deleted", "message": "Account successfully deleted"}

def get_current_user(request: Request) -> dict:
    """
    Returns authenticated user dict. Raises 401 if not logged in.
    """
    email = request.session.get("user_email")
    if not email:
        raise HTTPException(status_code=401, detail="Not authenticated. Please login.")
    role = "admin" if email == ADMIN_EMAIL else "user"
    mgr = _get_saas_manager()
    tenant = None
    if mgr:
        tenant = mgr.get_tenant_by_email(email)
        if not tenant:
            tenant = mgr.ensure_tenant(email)
    return {"email": email, "role": role, "tenant": tenant}


def get_tenant_db_for_request(request: Request):
    """
    Returns (sqlite3.Connection, tenant_dict) for the requesting user.

    Routing logic (per architecture blueprint §3D):
      - Normal user  → their own tenant_XXXX.db from tenants/ folder
      - Admin        → if X-Impersonate-Tenant header is set, that tenant's db;
                       otherwise admin's own tenant db
      - Fallback     → admin tenant DB (single-tenant mode, no TenantManager)

    Raises HTTP 403 if a non-admin tries to impersonate.
    """
    user = get_current_user(request)
    mgr = _get_saas_manager()

    if mgr is None:
        # Single-tenant fallback
        return get_db(), {}

    impersonate_id = request.headers.get("X-Impersonate-Tenant", "").strip()

    if impersonate_id:
        if user["role"] != "admin":
            raise HTTPException(status_code=403, detail="Only admins can impersonate tenants.")
        con = mgr.get_tenant_db_by_id(impersonate_id)
        if con is None:
            raise HTTPException(status_code=404, detail=f"Tenant {impersonate_id!r} not found.")
        rows = mgr.get_all_tenants()
        target = next((t for t in rows if t["id"] == impersonate_id), {})
        return con, target

    # Normal path — use the requesting user's own tenant
    tenant = user.get("tenant") or {}
    tenant_id = tenant.get("id") if tenant else None
    if not tenant_id:
        # Tenant row missing — fall back gracefully
        return get_db(), {}

    con = mgr.get_tenant_db_by_id(tenant_id)
    if con is None:
        raise HTTPException(status_code=503, detail="Tenant database unavailable.")
    return con, tenant


def ensure_db_migrations(conn: sqlite3.Connection):
    """Idempotent migration: adds any missing columns from v2 schema."""
    try:
        event_cols = {row["name"] for row in conn.execute("PRAGMA table_info(events)").fetchall()}
        for col, col_type in {
            "raw_json_original": "TEXT",
            "raw_json_normalized": "TEXT",
        }.items():
            if col not in event_cols:
                conn.execute(f"ALTER TABLE events ADD COLUMN {col} {col_type}")

        alert_cols = {row["name"] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()}
        for col, col_type in {
            "source_process_guid":   "TEXT",
            "source_agent_name":     "TEXT",
            "source_type":           "TEXT",
            "source_channel":        "TEXT",
            "source_event_id":       "INTEGER",
            "source_wazuh_ts_epoch": "INTEGER",
            # v2 dual-layer + T1027 overlay
            "confidence":            "TEXT DEFAULT 'HIGH'",
            "amsi_matched_patterns": "TEXT",
            "no_amsi_corroboration": "INTEGER DEFAULT 0",
            "obfuscation_score":     "REAL DEFAULT 0.0",
        }.items():
            if col not in alert_cols:
                conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} {col_type}")

        edge_cols = {row["name"] for row in conn.execute("PRAGMA table_info(process_edges)").fetchall()}
        if "host_id" not in edge_cols:
            conn.execute("ALTER TABLE process_edges ADD COLUMN host_id TEXT")

        conn.execute(
            """
            UPDATE events
            SET raw_json_original = COALESCE(raw_json_original, raw_json),
                raw_json_normalized = COALESCE(raw_json_normalized, raw_json)
            WHERE raw_json_original IS NULL OR raw_json_normalized IS NULL
            """
        )

        # Ensure raw_detections staging table exists (created by ingestor but API may start first)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS raw_detections (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                process_guid      TEXT,
                endpoint_id       TEXT,
                ts                INTEGER NOT NULL,
                layer             TEXT    NOT NULL,
                technique         TEXT    NOT NULL,
                matched_pattern   TEXT,
                obfuscation_score REAL    DEFAULT 0.0,
                event_id_fk       INTEGER,
                merged            INTEGER NOT NULL DEFAULT 0,
                created_at        INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                UNIQUE(event_id_fk, layer, technique)
            )
        """)
        conn.commit()
    except sqlite3.OperationalError:
        pass



def row_to_dict(row: sqlite3.Row | None) -> Dict[str, Any]:
    return dict(row) if row else {}


def parse_raw_event(row: sqlite3.Row | Dict[str, Any] | None) -> Dict[str, Any]:
    if not row:
        return {}
    try:
        row_dict = dict(row)
        raw_json = (
            row_dict.get("raw_json_normalized")
            or row_dict.get("raw_json")
            or row_dict.get("raw_json_original")
            or "{}"
        )
        return json.loads(raw_json)
    except Exception:
        return {}


def win_system(raw: Dict[str, Any]) -> Dict[str, Any]:
    return raw.get("data", {}).get("win", {}).get("system", {}) or {}


def win_eventdata(raw: Dict[str, Any]) -> Dict[str, Any]:
    return raw.get("data", {}).get("win", {}).get("eventdata", {}) or {}


def ci_get(obj: dict, *keys, default=None):
    """Case-insensitive dict get with support for Wazuh/Sysmon field variants."""
    if not isinstance(obj, dict):
        return default
    
    # Try exact match first for speed
    for k in keys:
        if k in obj and obj[k] is not None:
            return obj[k]
            
    # Fallback to case-insensitive
    lower_keys = {k.lower() for k in keys}
    for k, v in obj.items():
        if k.lower() in lower_keys and v is not None:
            return v
    return default

def normalize_guid(g: str | None) -> str | None:
    if not g:
        return None
    g = str(g).strip().lower()
    if not g.startswith('{'):
        g = '{' + g
    if not g.endswith('}'):
        g = g + '}'
    return g


def severity_score(severity: str) -> int:
    return {"critical": 10, "high": 8, "medium": 5, "low": 2}.get((severity or "").lower(), 1)


def source_layer(channel: str | None) -> str:
    c = (channel or "").lower()
    if "sysmon" in c:
        return "sysmon"
    if c == "ishax-amsi":
        return "amsi"
    if c == "security":
        return "windows-security"
    if c == "system":
        return "windows-system"
    return c or "unknown"


RAW_JSON_SEARCH_EXPR = "COALESCE(raw_json_normalized, raw_json, raw_json_original)"


def extract_amsi_payload(edata: Dict[str, Any]) -> Dict[str, Any]:
    raw_payload = ci_get(edata, "param1", "data", default="") or ""
    if not raw_payload:
        return {}
    try:
        return json.loads(raw_payload)
    except Exception:
        return {}


def extract_process_guid(raw: Dict[str, Any]) -> Optional[str]:
    edata = win_eventdata(raw)
    guid = ci_get(edata, "ProcessGuid", "processGuid")
    if guid:
        return normalize_guid(str(guid))
    system = win_system(raw)
    if (ci_get(system, "channel", default="") or "").lower() == "ishax-amsi":
        amsi = extract_amsi_payload(edata)
        guid = ci_get(amsi, "process_guid", "processGuid")
        if guid:
            return normalize_guid(str(guid))
    return None


def process_node_from_row(row: sqlite3.Row | None) -> Optional[Dict[str, Any]]:
    if not row:
        return None
    return {
        "process_guid": row["process_guid"],
        "parent_process_guid": row["parent_process_guid"],
        "image": row["image"] or "Unknown",
        "command_line": row["command_line"] or "",
        "pid": row["pid"],
        "user_name": row["user_name"],
        "host_id": row["host_id"],
        "event_timestamp": row["start_time"],
        "end_time": row["end_time"],
    }


def fallback_process_from_event(event_row: sqlite3.Row | None, process_guid: str) -> Optional[Dict[str, Any]]:
    if not event_row:
        return None
    raw = parse_raw_event(event_row)
    edata = win_eventdata(raw)
    return {
        "process_guid": process_guid,
        "parent_process_guid": ci_get(edata, "ParentProcessGuid", "parentProcessGuid"),
        "image": ci_get(edata, "Image", "image", "ImagePath", "imagePath", "SourceImage", "sourceImage", default="Unknown"),
        "command_line": ci_get(edata, "CommandLine", "commandLine", default=""),
        "pid": ci_get(edata, "ProcessId", "processId"),
        "user_name": ci_get(edata, "User", "user"),
        "host_id": event_row["agent_name"] or "unknown",
        "event_timestamp": event_row["wazuh_ts"],
        "end_time": None,
    }


def load_process_chain(conn: sqlite3.Connection, process_guid: Optional[str]) -> Optional[Dict[str, Any]]:
    if not process_guid:
        return None
    self_row = conn.execute("SELECT * FROM process_nodes WHERE process_guid = ?", (process_guid,)).fetchone()
    self_node = process_node_from_row(self_row)
    if not self_node:
        event_row = conn.execute(
            f"SELECT * FROM events WHERE {RAW_JSON_SEARCH_EXPR} LIKE ? LIMIT 1",
            (f"%{process_guid}%",),
        ).fetchone()
        self_node = fallback_process_from_event(event_row, process_guid)
    if not self_node:
        return None

    parents = conn.execute(
        """
        WITH RECURSIVE ancestors AS (
            SELECT * FROM process_nodes WHERE process_guid = ?
            UNION ALL
            SELECT p.* FROM process_nodes p
            INNER JOIN ancestors a ON p.process_guid = a.parent_process_guid
        )
        SELECT * FROM ancestors WHERE process_guid != ?
        """,
        (process_guid, process_guid),
    ).fetchall()
    children = conn.execute(
        "SELECT * FROM process_nodes WHERE parent_process_guid = ? ORDER BY start_time DESC LIMIT 25",
        (process_guid,),
    ).fetchall()
    return {
        "self": self_node,
        "parents": [process_node_from_row(r) for r in parents if process_node_from_row(r)],
        "children": [process_node_from_row(r) for r in children if process_node_from_row(r)],
    }


def format_alert(conn: sqlite3.Connection, alert_row: sqlite3.Row) -> Dict[str, Any]:
    event_row = conn.execute("SELECT * FROM events WHERE id = ?", (alert_row["event_id_fk"],)).fetchone()
    raw = parse_raw_event(event_row)
    process_guid = alert_row["source_process_guid"] or extract_process_guid(raw)
    event = row_to_dict(event_row)
    channel = alert_row["source_channel"] or event.get("channel")
    return {
        "alert_id": str(alert_row["id"]),
        "rule_id": alert_row["rule_id"],
        "source_layer": source_layer(channel),
        "technique_id": alert_row["mitre_technique"],
        "rule_name": alert_row["rule_name"],
        "severity_score": severity_score(alert_row["severity"]),
        "raw_event_ref": process_guid,
        "source_table": "events",
        "host_id": alert_row["source_agent_name"] or event.get("agent_name"),
        "source_type": alert_row["source_type"] if "source_type" in alert_row.keys() else event.get("source_type"),
        "created_at": utc_from_epoch(alert_row["fired_at"]),
        "suppressed": False,
        "summary": alert_row["summary"],
        "event_id": alert_row["source_event_id"] or event.get("event_id"),
        "channel": channel,
        "process_chain": load_process_chain(conn, process_guid),
    }


def build_process_tree(conn: sqlite3.Connection, root_guid: str, host_id: str | None = None) -> Dict[str, Any]:
    rows = conn.execute(
        """
        WITH RECURSIVE ancestors AS (
            SELECT process_guid, parent_process_guid, pid, image, command_line, user_name, host_id, start_time, end_time
            FROM process_nodes
            WHERE process_guid = ? AND (? IS NULL OR host_id = ?)
            UNION ALL
            SELECT p.process_guid, p.parent_process_guid, p.pid, p.image, p.command_line, p.user_name, p.host_id, p.start_time, p.end_time
            FROM process_nodes p
            INNER JOIN ancestors a ON p.process_guid = a.parent_process_guid
            WHERE ? IS NULL OR p.host_id = ?
        ),
        descendants AS (
            SELECT process_guid, parent_process_guid, pid, image, command_line, user_name, host_id, start_time, end_time
            FROM process_nodes
            WHERE process_guid IN (SELECT process_guid FROM ancestors)
            UNION ALL
            SELECT p.process_guid, p.parent_process_guid, p.pid, p.image, p.command_line, p.user_name, p.host_id, p.start_time, p.end_time
            FROM process_nodes p
            INNER JOIN descendants d ON p.parent_process_guid = d.process_guid
            WHERE ? IS NULL OR p.host_id = ?
        )
        SELECT DISTINCT * FROM descendants
        """,
        (root_guid, host_id, host_id, host_id, host_id, host_id, host_id),
    ).fetchall()

    nodes = [process_node_from_row(row) for row in rows]
    nodes = [node for node in nodes if node]
    edges = []
    seen_edges = set()
    for node in nodes:
        parent = node["parent_process_guid"]
        if parent:
            edge = (parent, node["process_guid"])
            if edge not in seen_edges:
                seen_edges.add(edge)
                edges.append({"source": edge[0], "target": edge[1]})

    if not nodes:
        event_row = conn.execute(
            f"SELECT * FROM events WHERE {RAW_JSON_SEARCH_EXPR} LIKE ? AND (? IS NULL OR agent_name = ?) LIMIT 1",
            (f"%{root_guid}%", host_id, host_id),
        ).fetchone()
        fallback = fallback_process_from_event(event_row, root_guid)
        if fallback:
            nodes.append(fallback)
            if fallback["parent_process_guid"]:
                edges.append({"source": fallback["parent_process_guid"], "target": root_guid})

    return {"nodes": nodes, "edges": edges, "alert_guids": [root_guid]}


def source_event_payload(event_row: sqlite3.Row | None) -> Dict[str, Any] | None:
    if not event_row:
        return None
    raw = parse_raw_event(event_row)
    event = row_to_dict(event_row)
    raw_original = event.get("raw_json_original")
    event.pop("raw_json", None)
    try:
        event["raw_json_original"] = json.loads(raw_original) if raw_original else None
    except Exception:
        event["raw_json_original"] = raw_original
    event["raw_json_normalized"] = raw
    event["raw_json"] = raw
    event["eventdata"] = win_eventdata(raw)
    event["system"] = win_system(raw)
    return event


def build_alert_evidence(conn: sqlite3.Connection, alert_row: sqlite3.Row) -> Dict[str, Any]:
    alert = format_alert(conn, alert_row)
    event_row = conn.execute("SELECT * FROM events WHERE id = ?", (alert_row["event_id_fk"],)).fetchone()
    raw = parse_raw_event(event_row)
    root_guid = alert_row["source_process_guid"] or extract_process_guid(raw)
    host_id = alert_row["source_agent_name"] or (event_row["agent_name"] if event_row else None)
    tree = build_process_tree(conn, root_guid, host_id) if root_guid else {"nodes": [], "edges": [], "alert_guids": []}
    process_map = {node["process_guid"]: node for node in tree["nodes"]}
    process_guids = list(process_map.keys())

    artifacts = {"network": [], "file": [], "registry": [], "process": []}
    for node in tree["nodes"]:
        artifacts["process"].append({
            "process_guid": node["process_guid"],
            "parent_process_guid": node["parent_process_guid"],
            "image": node["image"],
            "command_line": node["command_line"],
            "pid": node["pid"],
            "user_name": node["user_name"],
            "host_id": node["host_id"],
            "timestamp": node["event_timestamp"],
        })

    if process_guids:
        placeholders = ",".join("?" for _ in process_guids)
        edge_rows = conn.execute(
            f"""
            SELECT process_guid, host_id, edge_type, target_label, timestamp
            FROM process_edges
            WHERE process_guid IN ({placeholders})
              AND (? IS NULL OR host_id = ? OR host_id IS NULL)
            ORDER BY timestamp DESC
            LIMIT 1000
            """,
            (*process_guids, host_id, host_id),
        ).fetchall()
        for row in edge_rows:
            proc = process_map.get(row["process_guid"], {})
            item = {
                "process_guid": row["process_guid"],
                "host_id": row["host_id"],
                "process_image": proc.get("image"),
                "target_label": row["target_label"],
                "timestamp": row["timestamp"],
            }
            if row["edge_type"] == "network":
                host, _, port = (row["target_label"] or "").partition(":")
                item.update({"destination_ip": host or None, "destination_port": port or None})
                artifacts["network"].append(item)
            elif row["edge_type"] == "file":
                item.update({"target_filename": row["target_label"]})
                artifacts["file"].append(item)
            elif row["edge_type"] == "registry":
                item.update({"target_object": row["target_label"]})
                artifacts["registry"].append(item)

    amsi_events = []
    if process_guids:
        for row in conn.execute(
            """
            SELECT id, wazuh_ts, agent_name, amsi_scan_result, amsi_content_name, amsi_content_hex,
                   raw_json_original, raw_json_normalized, raw_json
            FROM events
            WHERE lower(channel) = 'ishax-amsi' AND (? IS NULL OR agent_name = ?)
            ORDER BY wazuh_ts_epoch DESC
            LIMIT 500
            """,
            (host_id, host_id),
        ).fetchall():
            amsi = extract_amsi_payload(win_eventdata(parse_raw_event(row)))
            if ci_get(amsi, "process_guid", "processGuid") in process_guids:
                amsi_events.append({
                    "id": str(row["id"]),
                    "process_guid": ci_get(amsi, "process_guid", "processGuid"),
                    "content_name": row["amsi_content_name"] or ci_get(amsi, "content_name", "contentName", default=""),
                    "scan_result": row["amsi_scan_result"] or 0,
                    "host_id": row["agent_name"],
                    "event_timestamp": row["wazuh_ts"],
                })

    edge_host_scope_complete = all(
        item.get("host_id") not in (None, "")
        for group in (artifacts["network"], artifacts["file"], artifacts["registry"])
        for item in group
    )
    def check_missing(edge_type: str, eids: list[int]) -> bool:
        if artifacts[edge_type]: return False
        if not process_guids: return False
        eid_cond = ",".join(str(e) for e in eids)
        for g in process_guids:
            row = conn.execute(
                f"SELECT 1 FROM events WHERE event_id IN ({eid_cond}) AND {RAW_JSON_SEARCH_EXPR} LIKE ? LIMIT 1",
                (f"%{g}%",),
            ).fetchone()
            if row: return True
        return False

    missing_amsi = False
    if not amsi_events and process_guids:
        for g in process_guids:
            row = conn.execute(
                f"SELECT 1 FROM events WHERE lower(channel) = 'ishax-amsi' AND {RAW_JSON_SEARCH_EXPR} LIKE ? LIMIT 1",
                (f"%{g}%",),
            ).fetchone()
            if row:
                missing_amsi = True
                break

    completeness = {
        "level": "process-backed" if root_guid and artifacts["process"] else "event-only",
        "has_source_event": event_row is not None,
        "has_process_guid": root_guid is not None,
        "has_process_node": len(artifacts["process"]) > 0,
        "host_scoped": host_id is not None,
        "edge_host_scope_complete": edge_host_scope_complete,
        "missing_network": check_missing("network", [3]),
        "missing_file": check_missing("file", [11, 23, 26]),
        "missing_registry": check_missing("registry", [12, 13, 14]),
        "missing_amsi": missing_amsi,
        "notes": [],
    }
    if not completeness["has_process_guid"]:
        completeness["notes"].append("Source event has no process GUID; graph artifacts are intentionally unavailable.")
    if root_guid and not completeness["has_process_node"]:
        completeness["notes"].append("Source process GUID exists but no matching process node was found.")
    if not edge_host_scope_complete:
        completeness["notes"].append("Some artifact rows were created before host_id was tracked on process_edges.")

    return {
        "alert": alert,
        "source_event": source_event_payload(event_row),
        "root_process_guid": root_guid,
        "host_id": host_id,
        "process_tree": tree,
        "artifacts": artifacts,
        "amsi": amsi_events,
        "completeness": completeness,
        "counts": {
            "processes": len(artifacts["process"]),
            "network": len(artifacts["network"]),
            "files": len(artifacts["file"]),
            "registry": len(artifacts["registry"]),
            "amsi": len(amsi_events),
        },
    }


@app.get("/stats")
def get_stats(request: Request):
    try:
        conn, _ = get_tenant_db_for_request(request)
        with conn:
            counts = {
                "events": conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
                "alerts": conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
                "process_events": conn.execute("SELECT COUNT(*) FROM events WHERE event_id IN (1,5,4688)").fetchone()[0],
                "network_events": conn.execute("SELECT COUNT(*) FROM events WHERE event_id = 3").fetchone()[0],
                "registry_events": conn.execute("SELECT COUNT(*) FROM events WHERE event_id IN (12,13,14)").fetchone()[0],
                "file_events": conn.execute("SELECT COUNT(*) FROM events WHERE event_id IN (11,23,26)").fetchone()[0],
                "amsi_events": conn.execute("SELECT COUNT(*) FROM events WHERE lower(channel) = 'ishax-amsi'").fetchone()[0],
                "image_load_events": conn.execute("SELECT COUNT(*) FROM events WHERE event_id = 7").fetchone()[0],
                "process_access_events": conn.execute("SELECT COUNT(*) FROM events WHERE event_id = 10").fetchone()[0],
                "remote_thread_events": conn.execute("SELECT COUNT(*) FROM events WHERE event_id = 8").fetchone()[0],
                "system_events": conn.execute("SELECT COUNT(*) FROM events WHERE lower(channel) IN ('security', 'system')").fetchone()[0],
            }
            last_alert_row = conn.execute("SELECT fired_at FROM alerts ORDER BY fired_at DESC LIMIT 1").fetchone()
            
            sev_rows = conn.execute("SELECT severity, COUNT(*) as c FROM alerts GROUP BY severity").fetchall()
            sev_counts = {"crit": 0, "high": 0, "med": 0, "low": 0}
            for row in sev_rows:
                score = severity_score(row["severity"] or "")
                if score >= 9: sev_counts["crit"] += row["c"]
                elif score >= 7: sev_counts["high"] += row["c"]
                elif score >= 5: sev_counts["med"] += row["c"]
                else: sev_counts["low"] += row["c"]
                
            return {
                "row_counts": counts, 
                "severity_counts": sev_counts,
                "last_alert": utc_from_epoch(last_alert_row[0]) if last_alert_row else None, 
                "utc": utc_now()
            }
    except sqlite3.OperationalError:
        return {"row_counts": {}, "severity_counts": {"crit": 0, "high": 0, "med": 0, "low": 0}, "last_alert": None, "utc": utc_now()}


@app.get("/health")
def get_health(request: Request):
    # Health check must not require auth because start_local.ps1 polls it on startup
    try:
        conn, _ = get_tenant_db_for_request(request)
    except HTTPException:
        conn = get_db()
    with conn:
        now_epoch = int(datetime.datetime.utcnow().timestamp())
        events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        hosts = conn.execute("SELECT COUNT(DISTINCT agent_name) FROM events WHERE agent_name IS NOT NULL AND agent_name != ''").fetchone()[0]
        process_nodes = conn.execute("SELECT COUNT(*) FROM process_nodes").fetchone()[0]
        process_edges = conn.execute("SELECT COUNT(*) FROM process_edges").fetchone()[0]
        last_event = conn.execute(
            "SELECT wazuh_ts, wazuh_ts_epoch, agent_name, channel, event_id FROM events ORDER BY wazuh_ts_epoch DESC LIMIT 1"
        ).fetchone()
        last_alert = conn.execute(
            "SELECT fired_at, rule_name, source_agent_name FROM alerts ORDER BY fired_at DESC LIMIT 1"
        ).fetchone()
        missing = {
            "agent_name": conn.execute("SELECT COUNT(*) FROM events WHERE agent_name IS NULL OR agent_name = ''").fetchone()[0],
            "channel": conn.execute("SELECT COUNT(*) FROM events WHERE channel IS NULL OR channel = ''").fetchone()[0],
            "event_id": conn.execute("SELECT COUNT(*) FROM events WHERE event_id IS NULL").fetchone()[0],
            "process_guid_alerts": conn.execute("SELECT COUNT(*) FROM alerts WHERE source_process_guid IS NULL OR source_process_guid = ''").fetchone()[0],
            "edge_host_id": conn.execute("SELECT COUNT(*) FROM process_edges WHERE host_id IS NULL OR host_id = ''").fetchone()[0],
        }

        lag_seconds = None
        if last_event:
            lag_seconds = max(0, now_epoch - int(last_event["wazuh_ts_epoch"]))

        warnings = []
        if events == 0:
            warnings.append("No events have been ingested.")
        if lag_seconds is not None and lag_seconds > 300:
            warnings.append("Last event is older than 5 minutes.")
        if missing["edge_host_id"] > 0:
            warnings.append("Some process_edges rows do not have host_id; they may be legacy rows.")

        return {
            "status": "healthy" if not warnings else "degraded",
            "db_exists": True,
            "utc": utc_now(),
            "pipeline": {
                "events": events,
                "alerts": alerts,
                "hosts": hosts,
                "process_nodes": process_nodes,
                "process_edges": process_edges,
            },
            "last_event": row_to_dict(last_event),
            "last_alert": row_to_dict(last_alert),
            "lag_seconds": lag_seconds,
            "missing_fields": missing,
            "warnings": warnings,
            "system_stats": {
                "cpu": psutil.cpu_percent(interval=0.1),
                "ram": psutil.virtual_memory().percent,
                "disk": psutil.disk_usage('/').percent
            },
        }


@app.get("/alerts")
def get_alerts(request: Request, limit: int = 50, offset: int = 0, severity_min: int | None = None, layer: str | None = None, technique: str | None = None):
    limit = max(1, min(int(limit or 50), 500))
    offset = max(0, int(offset or 0))
    conn, _ = get_tenant_db_for_request(request)
    with conn:
        where = []
        params: list[Any] = []
        if technique:
            where.append("mitre_technique = ?")
            params.append(technique)
        if severity_min is not None:
            min_score = int(severity_min)
            allowed = []
            for sev in ("low", "medium", "high", "critical"):
                if severity_score(sev) >= min_score:
                    allowed.append(sev)
            if allowed:
                where.append(f"severity IN ({','.join('?' for _ in allowed)})")
                params.extend(allowed)
            else:
                return {"total": 0, "limit": limit, "offset": offset, "alerts": []}
        where_sql = f"WHERE {' AND '.join(where)}" if where else ""
        total = conn.execute(f"SELECT COUNT(*) FROM alerts {where_sql}", params).fetchone()[0]
        rows = conn.execute(
            f"""
            SELECT id, fired_at, rule_id, rule_name, mitre_technique, severity,
                   summary, event_id_fk, source_process_guid, source_agent_name,
                   source_type, source_channel, source_event_id, source_wazuh_ts_epoch
            FROM alerts
            {where_sql}
            ORDER BY fired_at DESC
            LIMIT ? OFFSET ?
            """,
            (*params, limit, offset),
        ).fetchall()
        alerts = [format_alert(conn, row) for row in rows]
        if layer:
            alerts = [a for a in alerts if a["source_layer"] == layer]
            total = len(alerts)
        return {"total": total, "limit": limit, "offset": offset, "alerts": alerts}


@app.get("/alerts/correlations")
def get_alert_correlations(request: Request, window_seconds: int = 300):
    window_seconds = max(1, min(int(window_seconds or 300), 3600))
    conn, _ = get_tenant_db_for_request(request)
    with conn:
        rows = conn.execute(
            """
            SELECT id, fired_at, rule_id, rule_name, mitre_technique, severity,
                   summary, event_id_fk, source_process_guid, source_agent_name,
                   source_type, source_channel, source_event_id, source_wazuh_ts_epoch
            FROM alerts
            WHERE source_agent_name IS NOT NULL
            ORDER BY source_agent_name ASC, fired_at ASC
            """
        ).fetchall()

        chains = []
        current_chain = []
        current_host = None
        
        for row in rows:
            alert = format_alert(conn, row)
            host = alert["host_id"]
            if host != current_host:
                if len(current_chain) > 1:
                    chains.append({"host_id": current_host, "alerts": current_chain, "start": current_chain[0]["created_at"], "end": current_chain[-1]["created_at"]})
                current_chain = [alert]
                current_host = host
            else:
                prev_time = int(datetime.datetime.fromisoformat(current_chain[-1]["created_at"].replace("Z", "+00:00")).timestamp())
                curr_time = int(datetime.datetime.fromisoformat(alert["created_at"].replace("Z", "+00:00")).timestamp())
                if curr_time - prev_time <= window_seconds:
                    current_chain.append(alert)
                else:
                    if len(current_chain) > 1:
                        chains.append({"host_id": current_host, "alerts": current_chain, "start": current_chain[0]["created_at"], "end": current_chain[-1]["created_at"]})
                    current_chain = [alert]
                    
        if len(current_chain) > 1:
            chains.append({"host_id": current_host, "alerts": current_chain, "start": current_chain[0]["created_at"], "end": current_chain[-1]["created_at"]})

        # Sort chains by end time descending (most recent first)
        chains.sort(key=lambda c: c["end"], reverse=True)
        return {"chains": chains}


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: int, request: Request):
    conn, _ = get_tenant_db_for_request(request)
    with conn:
        row = conn.execute(
            """
            SELECT id, fired_at, rule_id, rule_name, mitre_technique, severity,
                   summary, event_id_fk, source_process_guid, source_agent_name,
                   source_type, source_channel, source_event_id, source_wazuh_ts_epoch
            FROM alerts
            WHERE id = ?
            """,
            (alert_id,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Alert not found")
        return format_alert(conn, row)


@app.get("/alerts/{alert_id}/evidence")
def get_alert_evidence(alert_id: int, request: Request):
    conn, _ = get_tenant_db_for_request(request)
    with conn:
        row = conn.execute(
            """
            SELECT id, fired_at, rule_id, rule_name, mitre_technique, severity,
                   summary, event_id_fk, source_process_guid, source_agent_name,
                   source_type, source_channel, source_event_id, source_wazuh_ts_epoch
            FROM alerts
            WHERE id = ?
            """,
            (alert_id,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Alert not found")
        return build_alert_evidence(conn, row)

class RuleToggle(BaseModel):
    enabled: bool



class AIQuery(BaseModel):
    question: str
    alert_id: Optional[int] = None
    host_id: Optional[str] = None
    hours: int = 24


def _ai_line(label: str, value: Any) -> str:
    return f"{label}: {value if value not in (None, '') else 'n/a'}"


def _latest_alert_rows(conn: sqlite3.Connection, host_id: str | None, hours: int, limit: int = 8):
    cutoff = int((datetime.datetime.utcnow() - datetime.timedelta(hours=hours)).timestamp())
    return conn.execute(
        """
        SELECT id, fired_at, rule_id, rule_name, mitre_technique, severity,
               summary, event_id_fk, source_process_guid, source_agent_name,
               source_type, source_channel, source_event_id, source_wazuh_ts_epoch
        FROM alerts
        WHERE fired_at >= ?
          AND (? IS NULL OR source_agent_name = ?)
        ORDER BY fired_at DESC
        LIMIT ?
        """,
        (cutoff, host_id, host_id, limit),
    ).fetchall()


def _ai_context(conn: sqlite3.Connection, payload: AIQuery, request: Request) -> dict:
    hours = max(1, min(int(payload.hours or 24), 168))
    health = get_health(request)
    stats = get_stats(request)
    rules_payload = get_rules()
    alerts = [format_alert(conn, row) for row in _latest_alert_rows(conn, payload.host_id, hours)]

    focus_evidence = None
    if payload.alert_id:
        row = conn.execute(
            """
            SELECT id, fired_at, rule_id, rule_name, mitre_technique, severity,
                   summary, event_id_fk, source_process_guid, source_agent_name,
                   source_type, source_channel, source_event_id, source_wazuh_ts_epoch
            FROM alerts
            WHERE id = ?
            """,
            (payload.alert_id,),
        ).fetchone()
        if row:
            focus_evidence = build_alert_evidence(conn, row)

    return {
        "hours": hours,
        "health": health,
        "stats": stats,
        "rules": rules_payload,
        "alerts": alerts,
        "focus_evidence": focus_evidence,
    }


def _build_ai_answer(question: str, context: dict) -> tuple[str, list[dict], list[str]]:
    q = (question or "").strip().lower()
    health = context["health"]
    stats = context["stats"]
    alerts = context["alerts"]
    rules = context["rules"].get("rules", [])
    focus = context.get("focus_evidence")
    counts = stats.get("row_counts", {})
    sev = stats.get("severity_counts", {})

    citations: list[dict] = [
        {"label": "health", "route": "/health"},
        {"label": "stats", "route": "/stats"},
        {"label": "recent alerts", "route": "/alerts"},
        {"label": "rules", "route": "/rules"},
    ]
    if focus:
        citations.append({"label": f"alert {focus['alert']['alert_id']} evidence", "route": f"/alerts/{focus['alert']['alert_id']}/evidence"})

    lines: list[str] = []
    lines.append("Analyst view from current SQLite/API data")
    lines.append("")
    lines.append(_ai_line("Pipeline status", health.get("status")))
    lines.append(_ai_line("Events", counts.get("events", 0)))
    lines.append(_ai_line("Alerts", counts.get("alerts", 0)))
    lines.append(_ai_line("Hosts", health.get("pipeline", {}).get("hosts", 0)))
    lines.append(_ai_line("Lag seconds", health.get("lag_seconds")))
    if health.get("warnings"):
        lines.append("Warnings: " + "; ".join(str(w) for w in health["warnings"]))

    if "rule" in q or "coverage" in q or "technique" in q:
        enabled = [r for r in rules if r.get("enabled")]
        disabled = [r for r in rules if not r.get("enabled")]
        techs = sorted({t for r in enabled for t in (r.get("technique_ids") or [])})
        lines.extend([
            "",
            f"Enabled rules: {len(enabled)} / {len(rules)}",
            "Active techniques: " + (", ".join(techs) if techs else "none visible"),
        ])
        if disabled:
            lines.append("Disabled rules: " + ", ".join(r.get("title", r.get("rule_id", "unknown")) for r in disabled[:6]))

    if "severity" in q or "priority" in q or "triage" in q or alerts:
        lines.extend([
            "",
            f"Severity posture: critical={sev.get('crit', 0)}, high={sev.get('high', 0)}, medium={sev.get('med', 0)}, low={sev.get('low', 0)}",
        ])
        if alerts:
            lines.append("Most recent alert focus:")
            for alert in alerts[:5]:
                lines.append(
                    f"- {alert['created_at']} | {alert['host_id'] or 'unknown'} | "
                    f"{alert['technique_id']} | score={alert['severity_score']} | {alert['rule_name']}"
                )
        else:
            lines.append(f"No alerts found in the last {context['hours']} hour(s) for the selected scope.")

    if focus:
        comp = focus.get("completeness", {})
        alert = focus["alert"]
        lines.extend([
            "",
            f"Focused alert {alert['alert_id']}: {alert['rule_name']}",
            _ai_line("Technique", alert.get("technique_id")),
            _ai_line("Host", alert.get("host_id")),
            _ai_line("Process GUID", focus.get("root_process_guid")),
            _ai_line("Evidence level", comp.get("level")),
            "Evidence counts: "
            f"process={focus['counts'].get('processes', 0)}, "
            f"network={focus['counts'].get('network', 0)}, "
            f"file={focus['counts'].get('files', 0)}, "
            f"registry={focus['counts'].get('registry', 0)}, "
            f"amsi={focus['counts'].get('amsi', 0)}",
        ])
        missing = [k for k, v in comp.items() if k.startswith("missing_") and v]
        if missing:
            lines.append("Potential linking gaps: " + ", ".join(missing))
        if comp.get("notes"):
            lines.append("Evidence notes: " + "; ".join(comp["notes"]))

    suggestions: list[str] = []
    if health.get("status") == "degraded":
        suggestions.append("Check Wazuh archive freshness and the ingestor process because health is degraded.")
    if sev.get("crit", 0) or sev.get("high", 0):
        suggestions.append("Start triage with the highest severity alerts and open evidence for process ancestry.")
    if focus and focus.get("completeness", {}).get("missing_amsi"):
        suggestions.append("Verify the AMSI watcher service and ETW session because raw AMSI data appears present but not linked.")
    if focus and not focus.get("root_process_guid"):
        suggestions.append("Treat this alert as event-only until the source event exposes a process GUID.")
    if not suggestions:
        suggestions.append("Review the newest alert evidence and confirm endpoint freshness before making a coverage claim.")

    lines.extend(["", "Next checks:"])
    lines.extend(f"- {item}" for item in suggestions)
    return "\n".join(lines), citations, suggestions


@app.post("/ai/query")
def query_ai(payload: AIQuery, request: Request):
    if not payload.question or not payload.question.strip():
        raise HTTPException(status_code=400, detail="Question is required")
    conn, _ = get_tenant_db_for_request(request)
    with conn:
        context = _ai_context(conn, payload, request)
        answer, citations, suggestions = _build_ai_answer(payload.question, context)
        return {
            "mode": "read-only-db-analyst",
            "answer": answer,
            "citations": citations,
            "suggested_checks": suggestions,
            "context": {
                "hours": context["hours"],
                "alerts_used": len(context["alerts"]),
                "has_focus_alert": context["focus_evidence"] is not None,
                "health_status": context["health"].get("status"),
            },
        }


# ---------------------------------------------------------------------------
# Rules endpoints — all backed by rules.db (no file I/O)
# ---------------------------------------------------------------------------

import sys as _sys
_sys.path.insert(0, PHASE2_DIR)
from rules_db import (
    get_rules as _db_get_rules,
    get_rule_yaml as _db_get_rule_yaml,
    upsert_rule as _db_upsert_rule,
    update_rule_yaml as _db_update_rule_yaml,
    update_rule_meta as _db_update_rule_meta,
    toggle_rule as _db_toggle_rule,
    delete_rule as _db_delete_rule,
    get_rule_stats as _db_get_rule_stats,
)


def _reload_sigma():
    """Hot-reload SIGMA_RULES from rules.db after any DB change."""
    try:
        from detector import load_sigma_rules
        load_sigma_rules()
    except Exception as exc:
        print(f"[WARN] SIGMA_RULES reload failed: {exc}", flush=True)


def _get_caller_info(request: Request) -> tuple[str | None, str | None, bool]:
    """Return (tenant_id, username, is_admin) from session."""
    session = getattr(request, "session", {}) or {}
    tenant_id  = session.get("tenant_id")
    username   = session.get("user_email") or session.get("username")
    is_admin   = session.get("is_admin", False)
    return tenant_id, username, is_admin


@app.get("/rules")
def get_rules(request: Request):
    tenant_id, _, is_admin = _get_caller_info(request)
    rows = _db_get_rules(tenant_id=tenant_id, is_admin=is_admin)
    rules = []
    for r in rows:
        import json as _json
        mitre = _json.loads(r.get("mitre_techniques") or "[]")
        tags  = _json.loads(r.get("tags") or "[]")
        rules.append({
            "rule_id":       r["rule_id"],
            "title":         r["title"],
            "description":   r["description"],
            "date":          r["date"],
            "severity":      r["severity"],
            "technique_ids": mitre,
            "tags":          tags,
            "enabled":       bool(r["enabled"]),
            "is_custom":     bool(r["is_custom"]),
            "is_global":     r["tenant_id"] is None,
            "tenant_id":     r["tenant_id"],
            "uploaded_by":   r.get("uploaded_by"),
            "hit_count":     r.get("hit_count", 0),
            "last_fired_at": r.get("last_fired_at"),
            "noise_score":   round(r.get("noise_score", 0.0), 3),
            "created_at":    r.get("created_at"),
            "updated_at":    r.get("updated_at"),
        })
    return {"count": len(rules), "rules": rules}


@app.get("/rules/stats")
def get_rule_stats():
    """Rule Performance Report — all rules ranked by hit_count."""
    import json as _json
    rows = _db_get_rule_stats()
    return {"stats": rows}


@app.post("/rules/{rule_id}/toggle")
def toggle_rule(rule_id: str, payload: RuleToggle):
    ok = _db_toggle_rule(rule_id, payload.enabled)
    if not ok:
        raise HTTPException(status_code=404, detail="Rule not found")
    _reload_sigma()
    return {"status": "success", "rule_id": rule_id, "enabled": payload.enabled}


@app.get("/rules/{rule_id}/yaml")
def get_rule_yaml(rule_id: str):
    raw = _db_get_rule_yaml(rule_id)
    if raw is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"rule_id": rule_id, "yaml": raw}


class RuleYamlUpdate(BaseModel):
    yaml: str


def _check_edit_permission(request: Request, rule_id: str):
    tenant_id, _, is_admin = _get_caller_info(request)
    from pipeline.rules_db import get_rules_db
    con = get_rules_db()
    try:
        row = con.execute("SELECT tenant_id FROM sigma_rules WHERE rule_id=?", (rule_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Rule not found")
        rule_tenant = row["tenant_id"]
    finally:
        con.close()
    if rule_tenant is None:
        if not is_admin:
            raise HTTPException(403, "Global rules can only be edited by admins")
    else:
        if not is_admin and rule_tenant != tenant_id:
            raise HTTPException(403, "Not authorized to edit this rule")


@app.put("/rules/{rule_id}/yaml")
def update_rule_yaml(rule_id: str, payload: RuleYamlUpdate, request: Request):
    """Update raw YAML — re-parses and updates all metadata columns atomically."""
    _check_edit_permission(request, rule_id)
    import yaml as _yaml
    try:
        _yaml.safe_load(payload.yaml)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {exc}")
    ok = _db_update_rule_yaml(rule_id, payload.yaml)
    if not ok:
        raise HTTPException(status_code=404, detail="Rule not found")
    _reload_sigma()
    return {"status": "saved", "rule_id": rule_id}


class RuleMetaUpdate(BaseModel):
    title:            Optional[str] = None
    description:      Optional[str] = None
    date:             Optional[str] = None
    severity:         Optional[str] = None
    tags:             Optional[list] = None
    mitre_techniques: Optional[list] = None
    rule_references:  Optional[list] = None
    falsepositives:   Optional[list] = None


@app.put("/rules/{rule_id}/meta")
def update_rule_meta(rule_id: str, payload: RuleMetaUpdate, request: Request):
    """Update rule metadata fields without touching detection YAML."""
    _check_edit_permission(request, rule_id)
    updates = {k: v for k, v in payload.dict().items() if v is not None}
    ok = _db_update_rule_meta(rule_id, updates)
    if not ok:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"status": "updated", "rule_id": rule_id}


@app.post("/rules/upload")
async def upload_rule(
    request: Request,
    yaml_text: str = Form(default=""),
    file: UploadFile = File(default=None),
):
    """Upload a new Sigma rule (paste or file). Stores in rules.db."""
    _, username, _ = _get_caller_info(request)
    tenant_id, _, _ = _get_caller_info(request)

    if file and file.filename:
        raw = (await file.read()).decode("utf-8")
    elif yaml_text.strip():
        raw = yaml_text
    else:
        raise HTTPException(status_code=400, detail="Provide yaml_text or upload a .yml file")

    try:
        result = _db_upsert_rule(
            raw_yaml=raw,
            is_custom=1,
            tenant_id=tenant_id,
            uploaded_by=username or "unknown",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"DB write failed: {exc}")

    _reload_sigma()
    return {
        "status":       "uploaded",
        "rule_id":      result["rule_id"],
        "title":        result["title"],
        "rules_loaded": len(SIGMA_RULES),
    }


@app.delete("/rules/{rule_id}")
def delete_rule(rule_id: str, request: Request):
    _check_edit_permission(request, rule_id)
    ok = _db_delete_rule(rule_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Rule not found")
    _reload_sigma()
    return {"status": "deleted", "rule_id": rule_id}



@app.get("/hosts")
def get_hosts(request: Request):
    conn, _ = get_tenant_db_for_request(request)
    with conn:
        rows = conn.execute(
            """
            SELECT agent_name, MIN(wazuh_ts_epoch) AS first_seen_epoch,
                   MAX(wazuh_ts_epoch) AS last_seen_epoch
            FROM events
            WHERE agent_name IS NOT NULL AND agent_name != ''
            GROUP BY agent_name
            ORDER BY last_seen_epoch DESC
            """
        ).fetchall()
        return {
            "hosts": [{
                "host_id": row["agent_name"],
                "pc_name": row["agent_name"],
                "registered_at": utc_from_epoch(row["first_seen_epoch"]),
                "last_seen": utc_from_epoch(row["last_seen_epoch"]),
            } for row in rows]
        }


@app.get("/process-tree")
def get_process_tree(request: Request, root_guid: str = None, host_id: str | None = None):
    if not root_guid:
        return {"nodes": [], "edges": [], "alert_guids": []}
    conn, _ = get_tenant_db_for_request(request)
    with conn:
        return build_process_tree(conn, root_guid, host_id)


@app.get("/events/{process_guid}")
def get_pivot_events(process_guid: str, type: str = "network", request: Request = None):
    conn, _ = get_tenant_db_for_request(request)
    with conn:
        rows = conn.execute(
            """
            SELECT edge_type, target_label, timestamp
            FROM process_edges
            WHERE process_guid = ? AND edge_type = ?
            ORDER BY timestamp DESC
            LIMIT 200
            """,
            (process_guid, type),
        ).fetchall()
        events = []
        for row in rows:
            item = {"type": row["edge_type"], "target_label": row["target_label"], "timestamp": row["timestamp"]}
            if row["edge_type"] == "network":
                host, _, port = (row["target_label"] or "").partition(":")
                item.update({"destination_ip": host or None, "destination_port": port or None})
            elif row["edge_type"] == "file":
                item.update({"target_filename": row["target_label"]})
            elif row["edge_type"] == "registry":
                item.update({"target_object": row["target_label"]})
            events.append(item)
        return {"events": events}


@app.get("/amsi")
def get_amsi(request: Request, limit: int = 100, offset: int = 0, process_guid: str | None = None, detected_only: bool = False, host_id: str | None = None):
    limit = max(1, min(int(limit or 100), 500))
    offset = max(0, int(offset or 0))
    conn, _ = get_tenant_db_for_request(request)
    with conn:
        rows = conn.execute(
            """
            SELECT id, wazuh_ts, agent_name, amsi_scan_result, amsi_content_name,
                   amsi_content_hex, raw_json_original, raw_json_normalized, raw_json
            FROM events
            WHERE lower(channel) = 'ishax-amsi'
            ORDER BY wazuh_ts_epoch DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()
        events = []
        for row in rows:
            raw = parse_raw_event(row)
            amsi = extract_amsi_payload(win_eventdata(raw))
            guid = ci_get(amsi, "process_guid", "processGuid")
            if process_guid and guid != process_guid:
                continue
            if host_id and row["agent_name"] != host_id:
                continue
            if detected_only and int(row["amsi_scan_result"] or 0) < 32768:
                continue
            events.append({
                "id": str(row["id"]),
                "pid": ci_get(amsi, "pid", "process_id", "processId"),
                "process_guid": guid,
                "content_name": row["amsi_content_name"] or ci_get(amsi, "content_name", "contentName", default=""),
                "content_hex": row["amsi_content_hex"] or ci_get(amsi, "content_hex", "contentHex", default=""),
                "scan_result": row["amsi_scan_result"] or 0,
                "host_id": row["agent_name"],
                "event_timestamp": row["wazuh_ts"],
                "raw_event": raw,
            })
        total = conn.execute("SELECT COUNT(*) FROM events WHERE lower(channel) = 'ishax-amsi'").fetchone()[0]
        return {"total": total, "limit": limit, "offset": offset, "events": events}


@app.get("/timeline")
def get_timeline(request: Request, host_id: str = "all", hours: int = 2):
    hours = max(1, min(int(hours or 2), 168))
    cutoff = int((datetime.datetime.utcnow() - datetime.timedelta(hours=hours)).timestamp())
    conn, _ = get_tenant_db_for_request(request)
    with conn:
        events = []
        alert_rows = conn.execute(
            """
            SELECT a.id, a.wazuh_event_id, a.fired_at, a.rule_name, a.severity
            FROM alerts a
            LEFT JOIN events e ON e.id = a.event_id_fk
            WHERE a.fired_at >= ? AND (e.agent_name = ? OR ? = 'all')
            ORDER BY a.fired_at DESC
            LIMIT 50
            """,
            (cutoff, host_id, host_id),
        ).fetchall()
        for row in alert_rows:
            events.append({
                "event_type": "alert",
                "id": row["wazuh_event_id"] or str(row["id"]),
                "label": f"Alert: {row['rule_name']}",
                "event_timestamp": utc_from_epoch(row["fired_at"]),
                "raw_json": None,
                "severity_score": severity_score(row["severity"]),
            })

        event_rows = conn.execute(
            """
            SELECT wazuh_id, event_id, channel, raw_json_original, raw_json_normalized, raw_json, wazuh_ts
            FROM events
            WHERE wazuh_ts_epoch >= ? AND (agent_name = ? OR ? = 'all')
            ORDER BY wazuh_ts_epoch DESC
            LIMIT 200
            """,
            (cutoff, host_id, host_id),
        ).fetchall()
        for row in event_rows:
            eid = row["event_id"]
            channel = (row["channel"] or "").lower()
            evt_type = "system"
            if channel == "ishax-amsi":
                evt_type = "amsi"
            elif eid in (1, 5, 7, 8, 9, 10, 4688):
                evt_type = "process"
            elif eid in (3, 22, 5156, 5158):
                evt_type = "network"
            elif eid in (11, 15, 23, 26):
                evt_type = "file"
            elif eid in (12, 13, 14):
                evt_type = "registry"
            elif eid in (4624, 4625, 4771):
                evt_type = "auth"

            label = f"Event ID {eid}"
            raw = parse_raw_event(row)
            edata = win_eventdata(raw)
            if evt_type == "process":
                if eid == 10:
                    src = ci_get(edata, 'SourceImage', default='unknown').split('\\')[-1]
                    tgt = ci_get(edata, 'TargetImage', default='unknown').split('\\')[-1]
                    label = f"Process Access: {src} -> {tgt}"
                elif eid == 7:
                    img = ci_get(edata, 'ImageLoaded', default='unknown').split('\\')[-1]
                    label = f"Image Load: {img}"
                else:
                    label = f"Process {ci_get(edata, 'Image', 'image', 'NewProcessName', default='')}"
            elif evt_type == "network":
                if eid == 22:
                    label = f"DNS Query: {ci_get(edata, 'QueryName', default='unknown')}"
                else:
                    label = f"Network connection to {ci_get(edata, 'DestinationIp', 'destinationIp', default='')}"
            elif evt_type == "file":
                label = f"File {ci_get(edata, 'TargetFilename', 'targetFilename', default='')}"
            elif evt_type == "registry":
                label = f"Registry {ci_get(edata, 'TargetObject', 'targetObject', default='')}"
            elif evt_type == "amsi":
                amsi = extract_amsi_payload(edata)
                label = f"AMSI scan: {ci_get(amsi, 'content_name', 'contentName', default='script buffer')}"
            elif evt_type == "auth":
                label = f"Auth Event ID {eid} for {ci_get(edata, 'TargetUserName', 'targetUserName', default='unknown')}"

            events.append({
                "event_type": evt_type,
                "id": str(row["wazuh_id"]),
                "label": label,
                "event_timestamp": row["wazuh_ts"],
                "raw_json": row["raw_json_normalized"] or row["raw_json"],
            })
        return {"events": events}


# ---------------------------------------------------------------------------
# Centralized Deployment Server Routes
# ---------------------------------------------------------------------------

from fastapi import Request, Response

@app.get("/deploy/sysmon.xml")
def get_sysmon_xml():
    import pathlib
    sysmon_path = pathlib.Path(__file__).parent.parent / "endpoint" / "sysmon_config.xml"
    try:
        with open(sysmon_path, "r", encoding="utf-8") as sf:
            return Response(content=sf.read(), media_type="application/xml")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/deploy/ossec.conf")
def get_ossec_conf(request: Request):
    host_ip = request.url.hostname
    conf = f"""<ossec_config>
  <client>
    <server>
      <address>{host_ip}</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <crypto_method>aes</crypto_method>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <localfile>
    <location>Application</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
    <query>Event/System[EventID != 5145 and EventID != 5156 and EventID != 5447 and EventID != 4703 and EventID != 4907 and EventID != 5152 and EventID != 5157]</query>
  </localfile>

  <localfile>
    <location>System</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
    <query>Event/System[EventID=4103 or EventID=4104 or EventID=4105 or EventID=4106]</query>
  </localfile>

  <localfile>
    <location>Microsoft-Windows-Windows Defender/Operational</location>
    <log_format>eventchannel</log_format>
    <query>Event/System[EventID=5001 or EventID=5004 or EventID=5007 or EventID=1116 or EventID=1117 or EventID=1119]</query>
  </localfile>

  <localfile>
    <location>ISHAX-AMSI</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>"""
    return Response(content=conf, media_type="application/xml")

@app.get("/deploy/install.ps1")
def get_install_script(request: Request):
    host_ip = request.url.hostname
    port = request.url.port or 8000
    base_url = f"http://{host_ip}:{port}"
    
    script = f"""<#
.SYNOPSIS
    ISHA-X EDR Robust Endpoint Deployment Script
#>

# 1. Admin Verification
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{
    Write-Host "[!] ERROR: This deployment script MUST be run as Administrator!" -ForegroundColor Red
    Write-Host "[!] Please close this PowerShell window, right-click PowerShell, select 'Run as Administrator', and try again." -ForegroundColor Yellow
    Exit
}}

# 2. TLS 1.2 Enforcement
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ErrorActionPreference = "Stop"

Write-Host "[*] Starting ISHA-X EDR Endpoint Setup..." -ForegroundColor Cyan

# 3. Wazuh Agent Installation (Smart Install)
try {{
    $wazuhService = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
    if ($wazuhService) {{
        Write-Host "[+] Wazuh Agent is already installed. Skipping download..." -ForegroundColor Yellow
    }} else {{
        Write-Host "[*] Downloading Wazuh Agent MSI..." -ForegroundColor Cyan
        Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.6-1.msi" -OutFile "$env:tmp\wazuh-agent.msi" -UseBasicParsing
        Write-Host "[*] Installing Wazuh Agent..." -ForegroundColor Cyan
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $env:tmp\wazuh-agent.msi /q WAZUH_MANAGER=`"{host_ip}`" WAZUH_REGISTRATION_SERVER=`"{host_ip}`"" -Wait -NoNewWindow -PassThru
        if ($process.ExitCode -ne 0) {{ throw "Wazuh MSI installation failed with exit code $($process.ExitCode)" }}
        Write-Host "[+] Wazuh Agent Installed Successfully!" -ForegroundColor Green
    }}
}} catch {{
    Write-Host "[X] Error during Wazuh installation: $_" -ForegroundColor Red
    Exit
}}

# 4. Applying Custom ossec.conf
try {{
    Write-Host "[*] Pulling Custom ossec.conf from Central Server..." -ForegroundColor Cyan
    $ossecConfPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"
    Invoke-WebRequest -Uri "{base_url}/deploy/ossec.conf" -OutFile $ossecConfPath -UseBasicParsing
    Write-Host "[+] Custom ossec.conf applied!" -ForegroundColor Green
}} catch {{
    Write-Host "[X] Error downloading ossec.conf. Is the FastAPI server reachable at {base_url}?" -ForegroundColor Red
    Exit
}}

# 5. Sysmon Installation (Smart Install)
try {{
    Write-Host "[*] Downloading Custom Sysmon Ruleset from Server..." -ForegroundColor Cyan
    $localSysmonConfig = "$env:TEMP\sysmonconfig.xml"
    Invoke-WebRequest -Uri "{base_url}/deploy/sysmon.xml" -OutFile $localSysmonConfig -UseBasicParsing

    $sysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    if ($sysmonService) {{
        Write-Host "[+] Sysmon is already installed. Updating ruleset dynamically..." -ForegroundColor Yellow
        Start-Process -FilePath "Sysmon64.exe" -ArgumentList "-c `"$localSysmonConfig`"" -Wait -NoNewWindow
    }} else {{
        Write-Host "[*] Downloading Sysmon Package..." -ForegroundColor Cyan
        Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip" -UseBasicParsing
        Expand-Archive -Path "$env:TEMP\Sysmon.zip" -DestinationPath "$env:TEMP\Sysmon" -Force
        Write-Host "[*] Installing Sysmon with ISHA-X Ruleset..." -ForegroundColor Cyan
        Start-Process -FilePath "$env:TEMP\Sysmon\Sysmon64.exe" -ArgumentList "-accepteula -i `"$localSysmonConfig`"" -Wait -NoNewWindow
    }}
    Write-Host "[+] Sysmon configured Successfully!" -ForegroundColor Green
}} catch {{
    Write-Host "[X] Error during Sysmon installation: $_" -ForegroundColor Red
}}

# 6. Service Verification
Write-Host "[*] Restarting and Verifying Services..." -ForegroundColor Cyan
Restart-Service -Name "WazuhSvc" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3

$wazuhCheck = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
$sysmonCheck = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue

$wazuhCheck.Status -eq 'Running' -and $sysmonCheck.Status -eq 'Running') {{
    Write-Host "[========================================================]" -ForegroundColor Green
    Write-Host "[+] SUCCESS: EDR Endpoint is LIVE!" -ForegroundColor Green
    Write-Host "[+] Both Wazuh and Sysmon are running properly." -ForegroundColor Green
    Write-Host "[========================================================]" -ForegroundColor Green
}} else {{
    Write-Host "[!] WARNING: Setup completed, but one or more services are not running." -ForegroundColor Yellow
}}
"""
    return Response(content=script, media_type="text/plain")


# ---------------------------------------------------------------------------
# Dynamic Installer Generation — /deploy/download-agent
# ---------------------------------------------------------------------------

def _build_ossec_conf(agent_id: str, agent_key: str, server_host: str) -> str:
    """Generate a custom ossec.conf with pre-registered agent credentials."""
    return f"""<ossec_config>
  <client>
    <server>
      <address>{server_host}</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <crypto_method>aes</crypto_method>
    <auto_restart>yes</auto_restart>
  </client>

  <!-- Pre-registered agent identity — DO NOT MODIFY -->
  <!-- agent_id: {agent_id} -->

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <localfile>
    <location>Application</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
    <query>Event/System[EventID != 5145 and EventID != 5156 and EventID != 5447 and EventID != 4703 and EventID != 4907 and EventID != 5152 and EventID != 5157]</query>
  </localfile>

  <localfile>
    <location>System</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
    <query>Event/System[EventID=4103 or EventID=4104 or EventID=4105 or EventID=4106]</query>
  </localfile>

  <localfile>
    <location>Microsoft-Windows-Windows Defender/Operational</location>
    <log_format>eventchannel</log_format>
    <query>Event/System[EventID=5001 or EventID=5004 or EventID=5007 or EventID=1116 or EventID=1117 or EventID=1119]</query>
  </localfile>

  <localfile>
    <location>ISHAX-AMSI</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>"""


async def _get_wazuh_token() -> str:
    """Authenticate against Wazuh API and return JWT token."""
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        r = await client.get(
            f"{WAZUH_API_BASE}/security/user/authenticate",
            auth=(WAZUH_API_USER, WAZUH_API_PASS),
        )
        r.raise_for_status()
        return r.json()["data"]["token"]


async def _wazuh_register_agent(agent_name: str) -> tuple[str, str]:
    """Pre-register an agent with Wazuh and return (agent_id, agent_key)."""
    token = await _get_wazuh_token()
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        r = await client.post(
            f"{WAZUH_API_BASE}/agents",
            headers={"Authorization": f"Bearer {token}"},
            json={"name": agent_name},
        )
        r.raise_for_status()
        resp_json = r.json()
        data = resp_json.get("data", {})
        
        # Wazuh 4.8 structure
        if "id" in data and "key" in data:
            return data["id"], data["key"]
        
        # Alternative structure (array of affected items)
        if "affected_items" in data and len(data["affected_items"]) > 0:
            item = data["affected_items"][0]
            if "id" in item and "key" in item:
                return item["id"], item["key"]
                
        # If both fail, raise descriptive error
        raise ValueError(f"Unexpected Wazuh API response: {resp_json}")


async def _wazuh_delete_agent(agent_id: str):
    """Remove an agent from Wazuh Manager."""
    try:
        token = await _get_wazuh_token()
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            await client.delete(
                f"{WAZUH_API_BASE}/agents",
                headers={"Authorization": f"Bearer {token}"},
                params={"agents_list": agent_id, "status": "all", "older_than": "0s"},
            )
    except Exception as e:
        print(f"[WARN] Wazuh delete agent {agent_id} failed: {e}", flush=True)


@app.get("/deploy/download-agent")
async def download_agent(request: Request, background_tasks: BackgroundTasks):
    """
    Dynamically compiles a personalised ISHAX_Setup.exe for the requesting user.
    Steps:
      1. Rate-limit check (60s cooldown per email)
      2. Pre-register a Wazuh agent and get agent_id + agent_key
      3. Map agent_id → tenant in master.db
      4. Generate custom ossec.conf with injected credentials
      5. Copy endpoint assets into temp dir
      6. Compile with iscc.exe
      7. Stream the .exe back and clean up
    """
    user = get_current_user(request)
    email = user["email"]
    tenant = user.get("tenant") or {}
    tenant_id = tenant.get("id")

    if not tenant_id:
        raise HTTPException(503, "Tenant record not found. Please try logging out and back in.")

    # Rate limit (10s — fast enough with NSIS)
    now = time.time()
    last_dl = _download_cooldown.get(email, 0)
    if now - last_dl < 10:
        wait = int(10 - (now - last_dl))
        raise HTTPException(429, f"Please wait {wait} more seconds before generating a new installer.")
    _download_cooldown[email] = now

    # Check makensis (NSIS) is available
    import shutil as _shutil
    iscc_available = _shutil.which(NSIS_PATH) is not None

    agent_name = f"ishax-{email.split('@')[0]}-{secrets.token_hex(3)}"

    # Try Wazuh pre-registration
    agent_id = None
    agent_key = None
    try:
        agent_id, agent_key = await _wazuh_register_agent(agent_name)
        mgr = _get_saas_manager()
        if mgr:
            mgr.register_agent(tenant_id=tenant_id, agent_id=agent_id, agent_name=agent_name)
        print(f"[Deploy] Agent pre-registered: {agent_id} → tenant {tenant_id}", flush=True)
    except Exception as e:
        print(f"[Deploy] Wazuh pre-registration failed: {e}", flush=True)
        # FALLBACK FOR CODESPACES / LOCAL DEV:
        # If Wazuh docker is not running, return the pre-compiled generic agent 
        # so the UI doesn't crash and the user still gets a valid installer.
        fallback_exe = os.path.join(ENDPOINT_SRC, "Output", "ISHAX_Setup.exe")
        if os.path.isfile(fallback_exe):
            print("[Deploy] Serving generic fallback installer...", flush=True)
            return FileResponse(
                fallback_exe,
                filename=f"ISHAX_Setup_{email.split('@')[0]}.exe",
                media_type="application/octet-stream",
            )
        raise HTTPException(
            503,
            f"Wazuh agent pre-registration failed: {e}. "
            "Ensure Wazuh Manager is running (check: docker ps) and try again in 30s."
        )

    # Build ossec.conf
    conf_content = _build_ossec_conf(agent_id, agent_key, SERVER_HOST)

    tmp = tempfile.mkdtemp(prefix="ishax_build_")
    try:
        # Required source files
        required = [
            "Sysmon64.exe",
            f"wazuh-agent-4.8.0-1.msi",
            "amsi_watcher.exe",
            "sysmon_config.xml",
            "ISHAX_Setup.nsi",
            "isolate.ps1",
            "unisolate.ps1",
        ]
        missing = [f for f in required if not os.path.isfile(os.path.join(ENDPOINT_SRC, f))]
        if missing:
            raise HTTPException(503, f"Endpoint assets missing on server: {missing}. Contact admin.")

        for fname in required:
            shutil.copy(os.path.join(ENDPOINT_SRC, fname), os.path.join(tmp, fname))

        # Tailscale installer — bundle if present in endpoint folder
        tailscale_src = os.path.join(ENDPOINT_SRC, "tailscale-setup.exe")
        if os.path.isfile(tailscale_src):
            shutil.copy(tailscale_src, os.path.join(tmp, "tailscale-setup.exe"))

        # Write dynamic ossec.conf
        with open(os.path.join(tmp, "ossec.conf"), "w", encoding="utf-8") as f:
            f.write(conf_content)

        if not iscc_available:
            raise HTTPException(
                503,
                "Installer compiler (makensis) not found on server. "
                "Run: sudo apt-get install -y nsis"
            )

        # Compile with NSIS (native Linux, no Wine needed)
        result = subprocess.run(
            [NSIS_PATH, "ISHAX_Setup.nsi"],
            capture_output=True,
            timeout=120,
            cwd=tmp,
        )
        if result.returncode != 0:
            err = result.stderr.decode(errors="replace") + result.stdout.decode(errors="replace")
            print(f"[Deploy] makensis failed:\n{err}", flush=True)
            raise HTTPException(500, "Installer compilation failed. Check server logs.")

        output_exe = os.path.join(tmp, "ISHAX_Setup.exe")
        if not os.path.isfile(output_exe):
            raise HTTPException(500, "Compiled .exe not found after makensis run.")

        # Move to a stable temp path (tmp folder gets cleaned after response)
        stable = os.path.join(tempfile.gettempdir(), f"ISHAX_Setup_{secrets.token_hex(6)}.exe")
        shutil.copy(output_exe, stable)

        background_tasks.add_task(shutil.rmtree, tmp, True)
        background_tasks.add_task(lambda p=stable: os.path.isfile(p) and os.remove(p))

        safe_name = f"ISHAX_Setup_{email.split('@')[0]}.exe"
        return FileResponse(
            stable,
            filename=safe_name,
            media_type="application/octet-stream",
        )

    except HTTPException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    except Exception as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise HTTPException(500, f"Installer generation error: {e}")


# ---------------------------------------------------------------------------
# Admin API endpoints
# ---------------------------------------------------------------------------

# ---- Whitelist management ----

@app.get("/admin/allowed-users")
def admin_get_allowed_users(request: Request):
    """List all whitelisted emails. Admin only."""
    user = get_current_user(request)
    if user["role"] != "admin":
        raise HTTPException(403, "Admin access required.")
    mgr = _get_saas_manager()
    if not mgr:
        raise HTTPException(503, "TenantManager unavailable.")
    return mgr.get_allowed_users()


class AllowUserRequest(BaseModel):
    email: str
    password: str = ""
    note: str = ""


@app.post("/admin/allowed-users")
def admin_add_allowed_user(body: AllowUserRequest, request: Request):
    """Add an email to the whitelist. Admin only. No server restart needed."""
    user = get_current_user(request)
    if user["role"] != "admin":
        raise HTTPException(403, "Admin access required.")
    mgr = _get_saas_manager()
    if not mgr:
        raise HTTPException(503, "TenantManager unavailable.")
    try:
        result = mgr.add_allowed_user(
            email=body.email,
            password=body.password,
            added_by=user["email"],
            note=body.note,
        )
        return {"status": "added", **result}
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.delete("/admin/allowed-users/{email:path}")
def admin_remove_allowed_user(email: str, request: Request):
    """Remove an email from the whitelist. Cannot remove super-admin. Admin only."""
    user = get_current_user(request)
    if user["role"] != "admin":
        raise HTTPException(403, "Admin access required.")
    email = email.strip().lower()
    if email == ADMIN_EMAIL:
        raise HTTPException(400, "Cannot remove the super-admin account.")
    mgr = _get_saas_manager()
    if not mgr:
        raise HTTPException(503, "TenantManager unavailable.")
    removed = mgr.remove_allowed_user(email)
    if not removed:
        raise HTTPException(404, f"{email} not found in whitelist.")
    return {"status": "removed", "email": email}


# ---- Tenant management ----

@app.get("/admin/tenants")
def admin_get_tenants(request: Request):
    """Return all tenants with DB size + agent count. Admin only."""
    user = get_current_user(request)
    if user["role"] != "admin":
        raise HTTPException(403, "Admin access required.")
    mgr = _get_saas_manager()
    if not mgr:
        raise HTTPException(503, "TenantManager unavailable.")
    tenants = mgr.get_all_tenants_with_stats()
    return tenants


@app.get("/admin/tenants/{tenant_id}/export")
def admin_export_tenant_db(tenant_id: str, request: Request):
    """Download a tenant's raw .db file for offline forensics. Admin only."""
    user = get_current_user(request)
    if user["role"] != "admin":
        raise HTTPException(403, "Admin access required.")
    mgr = _get_saas_manager()
    if not mgr:
        raise HTTPException(503, "TenantManager unavailable.")
    from multi_tenant_manager import TENANT_DB_DIR
    row = mgr._master.execute("SELECT email, db_filename FROM tenants WHERE id = ?", (tenant_id,)).fetchone()
    if not row:
        raise HTTPException(404, f"Tenant {tenant_id} not found.")
    db_path = TENANT_DB_DIR / row["db_filename"]
    if not db_path.exists():
        raise HTTPException(404, "DB file not found on disk.")
    safe_email = row["email"].replace("@", "_at_").replace(".", "_")
    return FileResponse(str(db_path), filename=f"ishax_{safe_email}.db", media_type="application/octet-stream")


@app.delete("/admin/agents/{agent_id}")
async def admin_revoke_agent(agent_id: str, request: Request):
    """Revoke an agent: removes from Wazuh + marks is_revoked in master.db. Admin only."""
    user = get_current_user(request)
    if user["role"] != "admin":
        raise HTTPException(403, "Admin access required.")
    mgr = _get_saas_manager()
    if not mgr:
        raise HTTPException(503, "TenantManager unavailable.")
    # Check agent exists
    row = mgr._master.execute("SELECT tenant_id FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
    if not row:
        raise HTTPException(404, f"Agent {agent_id} not found.")
    # Call Wazuh API (best-effort)
    await _wazuh_delete_agent(agent_id)
    # Mark revoked in master.db
    mgr._master.execute("UPDATE agents SET is_revoked = 1 WHERE agent_id = ?", (agent_id,))
    mgr._master.commit()
    mgr._agent_cache.pop(agent_id, None)
    return {"status": "revoked", "agent_id": agent_id}


@app.delete("/admin/tenants/{tenant_id}")
async def admin_purge_tenant(tenant_id: str, request: Request):
    """Permanently delete a tenant: revoke all agents in Wazuh, delete DB file, remove master.db rows. Admin only."""
    user = get_current_user(request)
    if user["role"] != "admin":
        raise HTTPException(403, "Admin access required.")
    mgr = _get_saas_manager()
    if not mgr:
        raise HTTPException(503, "TenantManager unavailable.")
    # Get all agents for this tenant and revoke in Wazuh
    agents = mgr.get_agents_for_tenant(tenant_id)
    for ag in agents:
        await _wazuh_delete_agent(ag["agent_id"])
    # Purge from master.db + delete .db file
    mgr.purge_tenant(tenant_id)
    return {"status": "purged", "tenant_id": tenant_id, "agents_revoked": len(agents)}



@app.get("/admin/agents/{agent_id}/revoke")
async def user_self_revoke_agent(agent_id: str, request: Request):
    """Users can revoke their OWN agents. Prevents cross-tenant abuse."""
    user = get_current_user(request)
    tenant = user.get("tenant") or {}
    tenant_id = tenant.get("id")
    mgr = _get_saas_manager()
    if not mgr or not tenant_id:
        raise HTTPException(503, "Service unavailable.")
    success = mgr.revoke_agent(agent_id, requesting_tenant_id=tenant_id)
    if not success:
        raise HTTPException(403, "Agent not found or does not belong to your account.")
    await _wazuh_delete_agent(agent_id)
    return {"status": "revoked", "agent_id": agent_id}


# ---------------------------------------------------------------------------
# Kill Switch — Network Isolation (Active Response)
# ---------------------------------------------------------------------------

async def _wazuh_active_response(agent_id: str, command: str):
    """Send an Active Response command to a specific agent via Wazuh API."""
    token = await _get_wazuh_token()
    async with httpx.AsyncClient(verify=False, timeout=20) as client:
        r = await client.put(
            f"{WAZUH_API_BASE}/active-response",
            headers={"Authorization": f"Bearer {token}"},
            params={"agents_list": agent_id},
            json={
                "command": command,
                "arguments": [],
                "alert": {
                    "data": {"srcip": "admin-triggered"},
                    "rule": {"description": "ISHAX Kill Switch"},
                },
            },
        )
        r.raise_for_status()
        return r.json()


@app.post("/admin/agents/{agent_id}/isolate")
async def admin_isolate_agent(agent_id: str, request: Request):
    """
    Isolate a PC: trigger isolate.ps1 via Wazuh Active Response.
    Blocks all network traffic on the endpoint EXCEPT the Wazuh connection.
    Admin only.
    """
    user = get_current_user(request)
    if user["role"] != "admin":
        raise HTTPException(403, "Admin access required.")
    mgr = _get_saas_manager()
    if not mgr:
        raise HTTPException(503, "TenantManager unavailable.")
    # Verify agent exists in master.db
    row = mgr._master.execute(
        "SELECT tenant_id, is_revoked FROM agents WHERE agent_id = ?", (agent_id,)
    ).fetchone()
    if not row:
        raise HTTPException(404, f"Agent {agent_id} not found.")
    if row["is_revoked"]:
        raise HTTPException(400, "Agent is already revoked — cannot isolate a revoked agent.")
    try:
        result = await _wazuh_active_response(agent_id, "ishax-isolate")
        # Mark isolated in master.db
        mgr._master.execute(
            "UPDATE agents SET is_isolated = 1 WHERE agent_id = ?", (agent_id,)
        )
        mgr._master.commit()
        print(f"[KillSwitch] Agent {agent_id} ISOLATED by {user['email']}", flush=True)
        return {"status": "isolated", "agent_id": agent_id, "wazuh_response": result}
    except Exception as e:
        raise HTTPException(500, f"Active Response failed: {e}. Is Wazuh running? Is agent online?")


@app.post("/admin/agents/{agent_id}/unisolate")
async def admin_unisolate_agent(agent_id: str, request: Request):
    """
    Restore network access: trigger unisolate.ps1 via Wazuh Active Response.
    Admin only.
    """
    user = get_current_user(request)
    if user["role"] != "admin":
        raise HTTPException(403, "Admin access required.")
    mgr = _get_saas_manager()
    if not mgr:
        raise HTTPException(503, "TenantManager unavailable.")
    row = mgr._master.execute(
        "SELECT tenant_id FROM agents WHERE agent_id = ?", (agent_id,)
    ).fetchone()
    if not row:
        raise HTTPException(404, f"Agent {agent_id} not found.")
    try:
        result = await _wazuh_active_response(agent_id, "ishax-unisolate")
        mgr._master.execute(
            "UPDATE agents SET is_isolated = 0 WHERE agent_id = ?", (agent_id,)
        )
        mgr._master.commit()
        print(f"[KillSwitch] Agent {agent_id} UNISOLATED by {user['email']}", flush=True)
        return {"status": "unisolated", "agent_id": agent_id, "wazuh_response": result}
    except Exception as e:
        raise HTTPException(500, f"Active Response failed: {e}. Is Wazuh running? Is agent online?")


@app.get("/admin/agents/{agent_id}/isolation-status")
def admin_get_isolation_status(agent_id: str, request: Request):
    """Get current isolation state of an agent. Admin only."""
    user = get_current_user(request)
    if user["role"] != "admin":
        raise HTTPException(403, "Admin access required.")
    mgr = _get_saas_manager()
    if not mgr:
        raise HTTPException(503, "TenantManager unavailable.")
    row = mgr._master.execute(
        "SELECT agent_id, is_isolated, is_revoked FROM agents WHERE agent_id = ?", (agent_id,)
    ).fetchone()
    if not row:
        raise HTTPException(404, f"Agent {agent_id} not found.")
    return {
        "agent_id": agent_id,
        "is_isolated": bool(row["is_isolated"]),
        "is_revoked": bool(row["is_revoked"]),
    }


# ---------------------------------------------------------------------------
# Serve pre-built React frontend (Codespace / production mode)
# FastAPI serves dist/ as static files — no Node/Vite needed at runtime.
# API routes defined above always take priority over the catch-all below.
# ---------------------------------------------------------------------------
import pathlib as _pathlib
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response

_DIST = _pathlib.Path(__file__).resolve().parent.parent / 'frontend' / 'dist'

if _DIST.is_dir():
    _assets = _DIST / 'assets'
    if _assets.is_dir():
        app.mount('/assets', StaticFiles(directory=str(_assets)), name='spa-assets')

    @app.get('/favicon.ico', include_in_schema=False)
    def _favicon():
        f = _DIST / 'favicon.ico'
        return FileResponse(str(f)) if f.exists() else Response(status_code=204)

    @app.get('/', include_in_schema=False)
    def _spa_root():
        return FileResponse(str(_DIST / 'index.html'))

    @app.get('/{_:path}', include_in_schema=False)
    def _spa_fallback(_: str):
        return FileResponse(str(_DIST / 'index.html'))

