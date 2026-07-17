#!/usr/bin/env python3
"""
EDR Project -- Phase 2: Wazuh archives.json → SQLite Ingestor
==============================================================
Reads Wazuh archives.json continuously (like `tail -f`), normalises
each Windows event into the `events` table, then hands the row to the
Sigma detection engine.

Usage (inside the Docker container or via `docker exec`):
    python ingestor.py

Or from the Windows host:
    docker exec -d single-node-wazuh.manager-1 \
        python3 /edr/ingestor.py

Environment variables (override defaults):
    ARCHIVES_JSON   path to archives.json
                    default: /var/ossec/logs/archives/archives.json
    EDR_DB_PATH     path to SQLite database
                    default: /edr/edr.db
    POLL_INTERVAL   seconds to sleep when no new data (float)
                    default: 0.5
"""

import hashlib
import json
import os
import queue
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Load environment variables from backend/.env if it exists
# ---------------------------------------------------------------------------
env_path = Path(__file__).parent.parent / "backend" / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def _resolve_archives_path() -> str:
    """
    R-2: Robust archives.json path resolution.
    Priority:
      1. ARCHIVES_JSON env var (always wins — explicit beats auto-detect)
      2. 'docker' sentinel → tail via docker exec (no direct file access needed)
      3. Auto-detect from known paths (Docker bind-mount, Linux native, Windows host)
    Returns 'stdin' if none found (caller can pipe events in for testing).
    """
    explicit = os.getenv("ARCHIVES_JSON", "").strip()
    if explicit:
        return explicit  # Env var wins — works for all platforms

    # Ordered candidate paths to try (most common first)
    candidates = [
        # Docker bind-mount (server/wazuh/docker-compose.yml: /tmp/wazuh_logs)
        "/tmp/wazuh_logs/archives/archives.json",
        # Native Linux Wazuh install
        "/var/ossec/logs/archives/archives.json",
        # Windows host: common Docker Desktop bind-mount targets
        r"C:\tmp\wazuh_logs\archives\archives.json",
        r"C:\wazuh_logs\archives\archives.json",
    ]
    for path in candidates:
        if Path(path).exists():
            print(f"[INFO] Auto-detected archives.json at: {path}", flush=True)
            return path

    # If running in Docker, use docker exec tail mode
    if Path("/.dockerenv").exists():
        print("[INFO] Running inside Docker — using docker tail mode", flush=True)
        return "docker"

    # No path found — warn loudly but don't crash; caller handles FileNotFoundError gracefully
    print(
        "[WARN] archives.json not found at any candidate path. "
        "Set ARCHIVES_JSON env var explicitly. Defaulting to Linux path.",
        flush=True,
    )
    return "/var/ossec/logs/archives/archives.json"


ARCHIVES_JSON   = _resolve_archives_path()
EDR_DB_PATH     = os.getenv("EDR_DB_PATH", str(Path(__file__).parent / "edr.db"))
SCHEMA_PATH     = str(Path(__file__).parent / "schema.sql")
POLL_INTERVAL   = float(os.getenv("POLL_INTERVAL", "0.5"))
SOURCE_TYPE     = os.getenv("EDR_SOURCE_TYPE", "").strip().lower()
RETENTION_DAYS  = int(os.getenv("EDR_RETENTION_DAYS", "14"))
WRITE_QUEUE_MAX = int(os.getenv("EDR_WRITE_QUEUE_MAX", "10000"))

# Multi-tenant mode: set MULTI_TENANT=1 in environment to enable SaaS routing.
# When disabled (default), ingestor works as a single-user lab tool (original behaviour).
MULTI_TENANT = os.getenv("MULTI_TENANT", "0").strip() == "1"

# Lazy-initialised singleton — only created when MULTI_TENANT=1
_tenant_manager = None

def _get_tenant_manager():
    """Return the module-level TenantManager singleton (imported lazily)."""
    global _tenant_manager
    if _tenant_manager is None:
        from multi_tenant_manager import get_manager
        _tenant_manager = get_manager()
    return _tenant_manager

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ts_to_epoch(ts_str: str) -> int:
    """Convert Wazuh ISO-8601 timestamp to unix seconds."""
    # e.g. "2026-07-09T16:55:18.232+0000"
    try:
        ts_str = ts_str.replace("+0000", "+00:00")
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.astimezone(timezone.utc).timestamp())
    except Exception:
        return int(time.time())


def safe_get(obj: dict, *keys, default=None):
    """Nested dict safe-get."""
    for k in keys:
        if not isinstance(obj, dict):
            return default
        obj = obj.get(k, default)
    return obj


def normalize_guid(g: str | None) -> str | None:
    if not g:
        return None
    g = str(g).strip().lower()
    if not g.startswith('{'):
        g = '{' + g
    if not g.endswith('}'):
        g = g + '}'
    return g


def ci_get(obj: dict, *keys, default=None):
    """Case-insensitive dict get with support for Wazuh/Sysmon field variants."""
    if not isinstance(obj, dict):
        return default
    lowered = {str(k).lower(): v for k, v in obj.items()}
    for key in keys:
        value = lowered.get(str(key).lower())
        if value is not None:
            return value
    return default


def infer_source_type(raw: dict, sys_: dict) -> str:
    configured = SOURCE_TYPE
    if configured in {"endpoint", "dc", "workgroup"}:
        return configured
    agent_name = str(safe_get(raw, "agent", "name", default="") or "").lower()
    computer = str(ci_get(sys_, "computer", "computerName", default="") or "").lower()
    channel = str(ci_get(sys_, "channel", default="") or "").lower()
    provider = str(ci_get(sys_, "providerName", "provider", default="") or "").lower()
    if channel == "directory service" or "directoryservices" in provider or agent_name.startswith("dc") or "-dc" in agent_name or computer.startswith("dc"):
        return "dc"
    if "." not in computer and "\\" not in computer:
        return "workgroup"
    return "endpoint"


def parse_hashes(value: str | None) -> dict:
    out = {}
    if not value:
        return out
    for part in str(value).replace(",", ";").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip()
    return out


# Maps event_id -> short source label for event_source column
_EID_TO_SOURCE: dict[int, str] = {
    1: "sysmon", 3: "sysmon", 5: "sysmon", 7: "sysmon", 8: "sysmon",
    10: "sysmon", 11: "sysmon", 12: "sysmon", 13: "sysmon", 14: "sysmon",
    15: "sysmon", 17: "sysmon", 18: "sysmon", 19: "sysmon", 20: "sysmon", 21: "sysmon",
    4104: "powershell",
    4624: "security", 4625: "security", 4697: "security", 4720: "security",
    4732: "security", 4662: "security", 4769: "security", 4771: "security",
    7045: "system",
}

# Maps event_id -> in-scope MITRE technique candidates at ingest time.
# This is metadata only; actual detections are controlled by detector.py.
_EID_TO_TECHNIQUE: dict[int, str] = {
    1:    "T1059.001/T1036/T1219/T1543.003",
    13:   "T1547.001/T1543.003",
    4104: "T1059.001",
    4697: "T1543.003",
    7045: "T1543.003",
}


def infer_event_source(channel: str | None, event_id: int | None) -> str:
    if event_id and event_id in _EID_TO_SOURCE:
        return _EID_TO_SOURCE[event_id]
    ch = (channel or "").lower()
    if "sysmon" in ch:     return "sysmon"
    if "powershell" in ch: return "powershell"
    if "security" in ch:   return "security"
    if "system" in ch:     return "system"
    if "amsi" in ch:       return "amsi"
    return "other"


def infer_technique(event_id: int | None) -> str | None:
    return _EID_TO_TECHNIQUE.get(event_id) if event_id else None


def normalise(raw: dict) -> dict | None:
    """
    Extract known fields from a Wazuh archives.json line.
    Returns None if the event isn't Windows or doesn't have an eventID.
    """
    win = safe_get(raw, "data", "win")
    if not win:
        return None

    sys_  = win.get("system", {})
    edata = win.get("eventdata", {})

    event_id = ci_get(sys_, "eventID", "eventId")
    if event_id is None:
        return None

    try:
        event_id = int(event_id)
    except (ValueError, TypeError):
        return None

    agent  = raw.get("agent", {})
    ts_str = raw.get("timestamp", "")
    raw_json_original_str = json.dumps(raw, separators=(",", ":"))

    # AMSI parsing
    amsi_scan_result = None
    amsi_content_name = None
    amsi_content_hex = None
    amsi_process_guid = None   # process_guid from AMSI watcher JSON payload
    channel = ci_get(sys_, "channel")
    if (channel or "").lower() == "ishax-amsi":
        amsi_raw = ci_get(edata, "param1", "data", default="") or ""
        if amsi_raw:
            try:
                # Handle double-escaped JSON from Wazuh event channel
                if '\\"' in amsi_raw:
                    amsi_raw = amsi_raw.replace('\\"', '"')
                if '\\\\' in amsi_raw:
                    amsi_raw = amsi_raw.replace('\\\\', '\\')
                    
                # Store the unescaped string back so json.dumps singly-escapes it
                if "param1" in edata:
                    edata["param1"] = amsi_raw
                elif "data" in edata:
                    edata["data"] = amsi_raw

                amsi_obj = json.loads(amsi_raw)
                
                # Normalize the process_guid directly in the payload so the normalized JSON
                # keeps the braced version while the original payload stays untouched.
                pg = amsi_obj.get("process_guid") or amsi_obj.get("processGuid")
                if pg:
                    norm_pg = normalize_guid(str(pg))
                    if "process_guid" in amsi_obj:
                        amsi_obj["process_guid"] = norm_pg
                    if "processGuid" in amsi_obj:
                        amsi_obj["processGuid"] = norm_pg
                    
                    # Re-serialize into edata so json.dumps(raw) captures the braced guid
                    new_amsi_raw = json.dumps(amsi_obj)
                    if "param1" in edata:
                        edata["param1"] = new_amsi_raw
                    elif "data" in edata:
                        edata["data"] = new_amsi_raw

                amsi_scan_result = int(ci_get(amsi_obj, "scan_result", "scanResult", default=0))
                amsi_content_name = str(ci_get(amsi_obj, "content_name", "contentName", default=""))
                amsi_content_hex = str(ci_get(amsi_obj, "content_hex", "contentHex", default=""))
                amsi_process_guid = ci_get(amsi_obj, "process_guid", "processGuid")
            except Exception as exc:
                print(
                    f"[WARN] malformed AMSI payload skipped "
                    f"(agent={agent.get('name') or 'unknown'}, event_id={event_id}, ts={ts_str}): {exc}",
                    flush=True,
                )


    raw_json_normalized_str = json.dumps(raw, separators=(",", ":"))

    out_dict = {
        "wazuh_id":        "", # Assigned below via hash
        "wazuh_ts":        ts_str,
        "wazuh_ts_epoch":  ts_to_epoch(ts_str),
        "agent_id":        agent.get("id"),
        "agent_name":      agent.get("name"),
        "agent_ip":        agent.get("ip"),
        "endpoint_id":     agent.get("name"),   # stable ID — agent_name is what we group by
        "event_source":    infer_event_source(channel, event_id),
        "technique_candidate": infer_technique(event_id),
        "source_type":     infer_source_type(raw, sys_),
        "channel":         channel,
        "event_id":        event_id,
        "provider_name":   ci_get(sys_, "providerName", "provider"),
        "computer":        ci_get(sys_, "computer", "computerName"),
        # eventdata mapped to normalised columns
        "subject_user":    ci_get(edata, "subjectUserName", "SubjectUserName"),
        "target_user":     ci_get(edata, "targetUserName", "TargetUserName"),
        "logon_type":      ci_get(edata, "logonType", "LogonType"),
        "service_name":    ci_get(edata, "serviceName", "ServiceName"),
        "image_path":      ci_get(edata, "imagePath", "ImagePath", "image", "Image", "NewProcessName"),
        "command_line":    ci_get(edata, "CommandLine", "commandLine", "ProcessCommandLine"),
        "parent_image":    ci_get(edata, "ParentImage", "parentImage"),
        "parent_command_line": ci_get(edata, "ParentCommandLine", "parentCommandLine"),
        "process_guid":    normalize_guid(ci_get(edata, "ProcessGuid", "processGuid", "SourceProcessGUID", "sourceProcessGuid") or amsi_process_guid),
        "parent_process_guid": normalize_guid(ci_get(edata, "ParentProcessGuid", "parentProcessGuid")),
        "source_image":    ci_get(edata, "SourceImage", "sourceImage"),
        "target_image":    ci_get(edata, "TargetImage", "targetImage"),
        "granted_access":  ci_get(edata, "GrantedAccess", "grantedAccess"),
        "destination_ip":  ci_get(edata, "DestinationIp", "destinationIp"),
        "destination_port":ci_get(edata, "DestinationPort", "destinationPort"),
        "target_filename": ci_get(edata, "TargetFilename", "targetFilename"),
        "hashes":          ci_get(edata, "Hashes", "hashes"),
        "target_object":   (ci_get(edata, "targetObject", "TargetObject") or "").replace("\\\\", "\\"),
        "details":         ci_get(edata, "Details", "details"),
        "ticket_options":  ci_get(edata, "ticketOptions", "TicketOptions"),
        "ticket_enc_type": ci_get(edata, "ticketEncryptionType", "TicketEncryptionType"),
        "access_mask":     ci_get(edata, "accessMask", "AccessMask"),
        "properties":      ci_get(edata, "properties", "Properties"),
        
        # New explicit spec fields
        "original_file_name": ci_get(edata, "OriginalFileName", "originalFileName"),
        # service_binary_path: ImagePath (EID 7045 System log) OR ServiceFileName (EID 4697 Security log)
        "service_binary_path": ci_get(edata, "ImagePath", "imagePath", "ServiceFileName", "serviceFileName", "service_binary_path"),
        "service_start_delta_seconds": 0, # To be computed by Sigma/Engine if needed, or left 0
        "command_line_flags": "", # Typically handled via command_line parsing
        "registry_path": (ci_get(edata, "TargetObject", "targetObject") or "").replace("\\\\", "\\").lower(),
        "process_hash": ci_get(edata, "Hashes", "hashes"),
        "process_path": ci_get(edata, "Image", "image"),
        "source_ip": ci_get(edata, "SourceIp", "sourceIp"),
        "username": ci_get(edata, "User", "user", "SubjectUserName", "TargetUserName"),

        # FIX C-2: Sysmon EID 10 ProcessAccess — CallTrace field (stack trace)
        # Used by proc_access_win_lsass_dump_comsvcs_dll.yml (LSASS dump detection)
        # Sysmon stores this as eventdata.CallTrace e.g. "C:\Windows\SYSTEM32\ntdll.dll+...|comsvcs.dll+..."
        "call_trace": ci_get(edata, "CallTrace", "callTrace"),

        # FIX C-1: Provider_Name from Windows event System section
        # Used by win_system_service_install_susp.yml (EID 7045, Provider_Name='Service Control Manager')
        # NOTE: provider_name comes from sys_ (System element), not edata (EventData)
        "provider_name": ci_get(sys_, "providerName", "provider", "ProviderName"),

        # AMSI specific fields
        "amsi_scan_result":amsi_scan_result,
        "amsi_content_name":amsi_content_name,
        "amsi_content_hex":amsi_content_hex,
        "raw_json_original": raw_json_original_str,
        "raw_json_normalized": raw_json_normalized_str,
        "raw_json":        raw_json_normalized_str,
    }

    # Dedup/idempotency key as required by spec
    dedup_hash = hashlib.sha256(f"{ts_str}_{raw_json_original_str}".encode()).hexdigest()
    out_dict["wazuh_id"] = dedup_hash
    return out_dict


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

class DB:
    def __init__(self, path: str):
        self.path = path
        self.con  = sqlite3.connect(path, check_same_thread=False)
        self.con.row_factory = sqlite3.Row
        self.con.execute("PRAGMA journal_mode=WAL")
        self.con.execute("PRAGMA synchronous=NORMAL")
        self.con.execute("PRAGMA busy_timeout=5000")
        self._apply_schema()
        print(f"[DB] SQLite opened: {path}", flush=True)

    def _apply_schema(self):
        with open(SCHEMA_PATH) as f:
            self.con.executescript(f.read())
        self._migrate()
        self.con.commit()

    def _migrate(self):
        # ---- events table ----
        existing_event_cols = {
            row["name"] for row in self.con.execute("PRAGMA table_info(events)").fetchall()
        }
        event_columns = {
            "source_type": "TEXT NOT NULL DEFAULT 'endpoint'",
            "endpoint_id": "TEXT",
            "event_source": "TEXT",
            "technique_candidate": "TEXT",
            "command_line": "TEXT",
            "parent_image": "TEXT",
            "parent_command_line": "TEXT",
            "process_guid": "TEXT",
            "parent_process_guid": "TEXT",
            "source_image": "TEXT",
            "target_image": "TEXT",
            "granted_access": "TEXT",
            "destination_ip": "TEXT",
            "destination_port": "TEXT",
            "target_filename": "TEXT",
            "hashes": "TEXT",
            "details": "TEXT",
            "original_file_name": "TEXT",
            "service_binary_path": "TEXT",
            "service_start_delta_seconds": "INTEGER",
            "command_line_flags": "TEXT",
            "registry_path": "TEXT",
            "process_hash": "TEXT",
            "process_path": "TEXT",
            "source_ip": "TEXT",
            "username": "TEXT",
            "call_trace": "TEXT",           # FIX C-2: Sysmon EID 10 CallTrace for LSASS rule
            "provider_name": "TEXT",        # FIX C-1: Windows Provider_Name for service install rule
            "raw_json_original": "TEXT",
            "raw_json_normalized": "TEXT",
        }
        for col, col_type in event_columns.items():
            if col not in existing_event_cols:
                self.con.execute(f"ALTER TABLE events ADD COLUMN {col} {col_type}")

        self.con.execute(
            """
            UPDATE events
            SET raw_json_original = COALESCE(raw_json_original, raw_json),
                raw_json_normalized = COALESCE(raw_json_normalized, raw_json)
            WHERE raw_json_original IS NULL OR raw_json_normalized IS NULL
            """
        )

        # ---- alerts table (v2 columns) ----
        existing_alert_cols = {
            row["name"] for row in self.con.execute("PRAGMA table_info(alerts)").fetchall()
        }
        alert_columns = {
            "source_process_guid":   "TEXT",
            "source_agent_name":     "TEXT",
            "source_type":           "TEXT",
            "source_channel":        "TEXT",
            "source_event_id":       "INTEGER",
            "source_wazuh_ts_epoch": "INTEGER",
            # v2: dual-layer confidence + T1027 overlay (§3, §5)
            "confidence":            "TEXT DEFAULT 'HIGH'",
            "amsi_matched_patterns": "TEXT",
            "no_amsi_corroboration": "INTEGER DEFAULT 0",
            "obfuscation_score":     "REAL DEFAULT 0.0",
        }
        for col, col_type in alert_columns.items():
            if col not in existing_alert_cols:
                self.con.execute(f"ALTER TABLE alerts ADD COLUMN {col} {col_type}")

        # ---- raw_detections table (created by schema.sql, ensure exists) ----
        self.con.execute("""
            CREATE TABLE IF NOT EXISTS raw_detections (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                process_guid      TEXT,
                endpoint_id       TEXT,
                ts                INTEGER NOT NULL,
                layer             TEXT    NOT NULL,
                technique         TEXT    NOT NULL,
                matched_pattern   TEXT,
                obfuscation_score REAL    DEFAULT 0.0,
                event_id_fk       INTEGER REFERENCES events(id) ON DELETE CASCADE,
                merged            INTEGER NOT NULL DEFAULT 0,
                created_at        INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                UNIQUE(event_id_fk, layer, technique)
            )
        """)
        self.con.execute(
            "CREATE INDEX IF NOT EXISTS idx_rd_technique_guid ON raw_detections(technique, process_guid)"
        )
        self.con.execute(
            "CREATE INDEX IF NOT EXISTS idx_rd_ts ON raw_detections(ts)"
        )
        self.con.execute(
            "CREATE INDEX IF NOT EXISTS idx_rd_merged ON raw_detections(merged)"
        )

        # ---- process_edges host_id back-compat ----
        existing_edge_cols = {
            row["name"] for row in self.con.execute("PRAGMA table_info(process_edges)").fetchall()
        }
        if "host_id" not in existing_edge_cols:
            self.con.execute("ALTER TABLE process_edges ADD COLUMN host_id TEXT")

        # ---- M-3: active_detections table (SQLite-backed upgrade tracker) ----
        self.con.execute("""
            CREATE TABLE IF NOT EXISTS active_detections (
                technique       TEXT    NOT NULL,
                process_guid    TEXT    NOT NULL DEFAULT '',
                endpoint_id     TEXT    NOT NULL DEFAULT '',
                alert_id        INTEGER REFERENCES alerts(id) ON DELETE CASCADE,
                ts              INTEGER NOT NULL,
                confidence      TEXT    NOT NULL,
                expires_at      INTEGER NOT NULL,
                PRIMARY KEY (technique, process_guid, endpoint_id)
            )
        """)
        self.con.execute(
            "CREATE INDEX IF NOT EXISTS idx_ad_expires ON active_detections(expires_at)"
        )

    def get_offset(self) -> int:
        cur = self.con.execute(
            "SELECT value FROM ingestion_state WHERE key='archives_offset'")
        row = cur.fetchone()
        return int(row[0]) if row else 0

    def set_offset(self, offset: int):
        self.con.execute(
            "UPDATE ingestion_state SET value=? WHERE key='archives_offset'",
            (str(offset),))
        self.con.commit()

    def insert_process_node(self, ev: dict):
        try:
            raw = json.loads(ev.get("raw_json", "{}"))
            evd = raw.get("data", {}).get("win", {}).get("eventdata", {})
            pguid = ci_get(evd, "ProcessGuid", "processGuid")
            if not pguid: return
            
            ppguid = ci_get(evd, "ParentProcessGuid", "parentProcessGuid")
            pid = ci_get(evd, "ProcessId", "processId")
            image = ci_get(evd, "Image", "image", default="Unknown")
            cmd = ci_get(evd, "CommandLine", "commandLine", default="")
            user = ci_get(evd, "User", "user", default="")
            ts = ev.get("wazuh_ts")
            host = ev.get("agent_name") or "unknown"
            
            self.con.execute(
                "INSERT OR IGNORE INTO process_nodes "
                "(process_guid, parent_process_guid, pid, image, command_line, user_name, host_id, start_time) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (pguid, ppguid, pid, image, cmd, user, host, ts)
            )
            self.con.commit()
        except Exception as e:
            print(f"[ERROR] insert_process_node: {e}", flush=True)

    def terminate_process_node(self, ev: dict):
        try:
            raw = json.loads(ev.get("raw_json", "{}"))
            evd = raw.get("data", {}).get("win", {}).get("eventdata", {})
            pguid = ci_get(evd, "ProcessGuid", "processGuid")
            if not pguid: return
            ts = ev.get("wazuh_ts")
            
            self.con.execute(
                "UPDATE process_nodes SET end_time = ? WHERE process_guid = ?",
                (ts, pguid)
            )
            self.con.commit()
        except Exception as e:
            print(f"[ERROR] terminate_process_node: {e}", flush=True)

    def insert_process_edge(self, ev: dict):
        try:
            raw = json.loads(ev.get("raw_json", "{}"))
            evd = raw.get("data", {}).get("win", {}).get("eventdata", {})
            pguid = ci_get(evd, "ProcessGuid", "processGuid")
            if not pguid: return
            
            ts = ev.get("wazuh_ts")
            eid = ev.get("event_id")
            
            edge_type = None
            target_label = ""
            
            if eid == 3:
                edge_type = "network"
                ip = ev.get("destination_ip") or ci_get(evd, "DestinationIp", "destinationIp", default="")
                port = ev.get("destination_port") or ci_get(evd, "DestinationPort", "destinationPort", default="")
                target_label = f"{ip}:{port}" if ip else "Unknown IP"
            elif eid == 11:
                edge_type = "file"
                target_label = ev.get("target_filename") or ci_get(evd, "TargetFilename", "targetFilename", default="")
            elif eid == 23:
                edge_type = "file"
                target_label = ev.get("target_filename") or ci_get(evd, "TargetFilename", "targetFilename", default="")
            elif eid in (12, 13, 14):
                edge_type = "registry"
                target_label = ev.get("target_object") or ci_get(evd, "TargetObject", "targetObject", default="")
                
            if edge_type and target_label:
                self.con.execute(
                    "INSERT INTO process_edges (process_guid, host_id, edge_type, target_label, timestamp) VALUES (?, ?, ?, ?, ?)",
                    (pguid, ev.get("agent_name") or "unknown", edge_type, target_label, ts)
                )
        except Exception as e:
            print(f"[ERROR] insert_process_edge: {e}", flush=True)

    def insert_event(self, ev: dict) -> int | None:
        """Returns the new rowid or None if duplicate (unique constraint on wazuh_id)."""
        cols   = list(ev.keys())
        placeh = ",".join("?" * len(cols))
        try:
            cur = self.con.execute(
                f"INSERT INTO events ({','.join(cols)}) VALUES ({placeh})",
                list(ev.values()))
            
            channel = (ev.get("channel") or "").lower()
            if ev.get("event_id") == 1 and channel == "microsoft-windows-sysmon/operational":
                self.insert_process_node(ev)
            elif ev.get("event_id") == 5 and channel == "microsoft-windows-sysmon/operational":
                self.terminate_process_node(ev)
            elif ev.get("event_id") in (3, 11, 12, 13, 14, 23) and channel == "microsoft-windows-sysmon/operational":
                self.insert_process_edge(ev)
                
            self.con.commit()
            return cur.lastrowid
        except sqlite3.IntegrityError:
            # Duplicate wazuh_id -- already ingested
            return None

    def insert_alert(self, alert: dict) -> int:
        cols   = list(alert.keys())
        placeh = ",".join("?" * len(cols))
        cur = self.con.execute(
            f"INSERT INTO alerts ({','.join(cols)}) VALUES ({placeh})",
            list(alert.values()))
        self.con.commit()
        return cur.lastrowid

    def link_alert_context(self, alert_id: int, source_event_id: int):
        row = self.con.execute(
            "SELECT source_process_guid, source_agent_name, source_wazuh_ts_epoch FROM alerts WHERE id = ?",
            (alert_id,),
        ).fetchone()
        if not row:
            return
        self.con.execute(
            "INSERT OR IGNORE INTO alert_event_links(alert_id, event_id, link_reason) VALUES (?, ?, ?)",
            (alert_id, source_event_id, "source"),
        )
        if row["source_process_guid"]:
            window_start = int(row["source_wazuh_ts_epoch"] or time.time()) - 60
            window_end = int(row["source_wazuh_ts_epoch"] or time.time()) + 60
            matches = self.con.execute(
                """
                SELECT id FROM events
                WHERE wazuh_ts_epoch BETWEEN ? AND ?
                  AND (? IS NULL OR agent_name = ?)
                  AND (
                    process_guid = ?
                    OR parent_process_guid = ?
                    OR COALESCE(raw_json_normalized, raw_json, raw_json_original) LIKE ?
                  )
                LIMIT 1000
                """,
                (
                    window_start, window_end,
                    row["source_agent_name"], row["source_agent_name"],
                    row["source_process_guid"], row["source_process_guid"],
                    f"%{row['source_process_guid']}%",
                ),
            ).fetchall()
            for ev_row in matches:
                self.con.execute(
                    "INSERT OR IGNORE INTO alert_event_links(alert_id, event_id, link_reason) VALUES (?, ?, ?)",
                    (alert_id, ev_row["id"], "process-window"),
                )
        self.con.commit()

    def enqueue_threat_intel(self, alert_id: int):
        rows = self.con.execute(
            """
            SELECT DISTINCT hashes, destination_ip
            FROM events e
            JOIN alert_event_links l ON l.event_id = e.id
            WHERE l.alert_id = ?
            """,
            (alert_id,),
        ).fetchall()
        now = int(time.time())
        for row in rows:
            sha256 = parse_hashes(row["hashes"]).get("sha256")
            if sha256 and len(sha256) == 64:
                self._queue_indicator(alert_id, sha256.lower(), "sha256", now)
            ip = row["destination_ip"]
            if ip and not str(ip).startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.", "127.")):
                self._queue_indicator(alert_id, str(ip), "ip", now)
        self.con.commit()

    def _queue_indicator(self, alert_id: int, indicator: str, indicator_type: str, now: int):
        fresh = self.con.execute(
            "SELECT checked_at, stale_after FROM threat_intel_cache WHERE indicator = ?",
            (indicator,),
        ).fetchone()
        if fresh and int(fresh["stale_after"]) > now:
            return
        self.con.execute(
            """
            INSERT OR IGNORE INTO threat_intel_queue(alert_id, indicator, indicator_type, next_run_at)
            VALUES (?, ?, ?, ?)
            """,
            (alert_id, indicator, indicator_type, now),
        )

    def prune_old_telemetry(self, retention_days: int = RETENTION_DAYS):
        cutoff = int(time.time()) - retention_days * 86400
        self.con.execute(
            """
            DELETE FROM events
            WHERE wazuh_ts_epoch < ?
              AND id NOT IN (SELECT event_id FROM alert_event_links)
              AND id NOT IN (SELECT event_id_fk FROM alerts WHERE event_id_fk IS NOT NULL)
            """,
            (cutoff,),
        )
        self.con.commit()


# ---------------------------------------------------------------------------
# Ingestion loop
# ---------------------------------------------------------------------------

def tail_file(path: str, offset: int):
    """
    Generator: yields (line, new_offset) for each complete JSON line
    appended to `path` after `offset` bytes.
    If path == "stdin", reads from standard input.
    """
    if path == "stdin":
        for line in sys.stdin:
            yield line.strip(), 0
    elif path == "docker":
        import subprocess
        print("[INFO] Tailing archives.json via docker exec...", flush=True)
        try:
            container_name = subprocess.check_output(
                ["docker", "ps", "--format", "{{.Names}}", "--filter", "name=wazuh.manager"], 
                text=True
            ).strip().split("\n")[0]
        except Exception:
            container_name = "wazuh-wazuh.manager-1"
            
        if not container_name:
            container_name = "wazuh-wazuh.manager-1"

        proc = subprocess.Popen(
            ["docker", "exec", container_name, "tail", "-F", "/var/ossec/logs/archives/archives.json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        for line in proc.stdout:
            yield line.strip(), 0  # Ignore offset for docker mode
    else:
        while True:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(offset)
                    while True:
                        line = fh.readline()
                        if not line:
                            time.sleep(POLL_INTERVAL)
                            continue
                        if not line.endswith("\n"):
                            # Incomplete line -- wait for more bytes
                            time.sleep(POLL_INTERVAL)
                            fh.seek(fh.tell() - len(line.encode()))
                            continue
                        offset = fh.tell()
                        yield line.strip(), offset
            except FileNotFoundError:
                print(f"[WARN] {path} not found, waiting ...", flush=True)
                time.sleep(5)
            except Exception as exc:
                print(f"[ERROR] tail loop: {exc}", flush=True)
                time.sleep(2)

def process_line(db: DB, line: str, new_offset: int, run_rules) -> bool:
    """
    Process one archives.json line:
      1. Parse + normalise
      2. Resolve tenant DB (multi-tenant mode) or use default DB (single-tenant mode)
      3. Insert into events table
      4. Run detection (Layer A AMSI + Layer B Sigma → merge → alerts)
      5. Handle new alerts (INSERT) and alert upgrades (UPDATE confidence)

    Multi-tenant routing (MULTI_TENANT=1):
      - Reads agent.id from the raw Wazuh JSON.
      - Looks up master.db via TenantManager to find the owning tenant's .db.
      - If agent_id is unknown/revoked, the log is DROPPED (security guardrail).
      - offset is still updated on the default db so the tail pointer advances.

    Old _alert_cooldown removed — dedup is now handled by the 30s
    raw_detections merge window in detector.py (§3). The merge's
    UNIQUE(event_id_fk, layer, technique) constraint prevents double-inserts.
    """
    if not line:
        return False
    try:
        raw = json.loads(line)
    except json.JSONDecodeError as exc:
        print(f"[WARN] malformed archives.json line skipped: {exc}", flush=True)
        if new_offset:
            db.set_offset(new_offset)
        return False

    ev = normalise(raw)
    if ev is None:
        if new_offset:
            db.set_offset(new_offset)
        return False

    # ------------------------------------------------------------------
    # Multi-tenant routing: resolve the correct DB for this agent
    # ------------------------------------------------------------------
    target_db = db  # default: single-tenant legacy mode
    if MULTI_TENANT:
        agent_id = str(raw.get("agent", {}).get("id", "") or "").strip()
        if not agent_id:
            # No agent ID in log — cannot route. Drop silently.
            if new_offset:
                db.set_offset(new_offset)
            return False
        mgr = _get_tenant_manager()
        tenant_con = mgr.get_tenant_db_by_agent(agent_id)
        if tenant_con is None:
            # Unknown or revoked agent — security guardrail: drop the log.
            print(
                f"[MULTI-TENANT] DROPPED: agent_id={agent_id!r} not registered in master.db",
                flush=True,
            )
            if new_offset:
                db.set_offset(new_offset)
            return False
        # Wrap the tenant connection in a DB-compatible object
        target_db = DB.__new__(DB)
        target_db.path = str(tenant_con)
        target_db.con  = tenant_con
        # Update last_seen timestamp in master.db (non-blocking)
        try:
            mgr.update_agent_last_seen(agent_id)
        except Exception:
            pass

    rowid = target_db.insert_event(ev)
    if rowid is None:
        if new_offset:
            db.set_offset(new_offset)
        return False

    try:
        from detector import register_alert_id
        alerts = run_rules(target_db.con, ev, rowid)
        for a in alerts:
            existing_id = a.pop("_existing_alert_id", None)

            if existing_id:
                # Upgrade existing MEDIUM alert to HIGH (AMSI corroboration arrived)
                try:
                    target_db.con.execute(
                        """UPDATE alerts
                           SET confidence = ?, severity = ?,
                               amsi_matched_patterns = ?,
                               no_amsi_corroboration = 0,
                               obfuscation_score = ?,
                               summary = ?
                           WHERE id = ?""",
                        (
                            a.get("confidence"),
                            a.get("severity"),
                            a.get("amsi_matched_patterns"),
                            a.get("obfuscation_score", 0.0),
                            a.get("summary"),
                            existing_id,
                        ),
                    )
                    target_db.con.commit()  # FIX H-5: was db.con.commit() — wrong DB in multi-tenant mode
                    print(
                        f"[ALERT-UPGRADE] id={existing_id} → "
                        f"{a.get('mitre_technique')} | HIGH | AMSI corroboration added",
                        flush=True,
                    )
                except Exception as upd_exc:
                    print(f"[ERROR] alert upgrade id={existing_id}: {upd_exc}", flush=True)
                else:
                    # M-4: Re-enqueue threat intel on upgrade — new evidence (AMSI patterns)
                    # may include hashes/IPs not present in the original cmdline event
                    try:
                        target_db.enqueue_threat_intel(existing_id)
                    except Exception as ti_exc:
                        print(f"[WARN] threat intel re-enqueue failed for upgraded alert {existing_id}: {ti_exc}", flush=True)
            else:
                # New alert — INSERT
                alert_id = target_db.insert_alert(a)
                target_db.link_alert_context(alert_id, rowid)
                target_db.enqueue_threat_intel(alert_id)
                # M-3: Pass con so register persists to active_detections DB table
                register_alert_id(
                    target_db.con,
                    a.get("mitre_technique", ""),
                    a.get("source_process_guid") or "",
                    a.get("source_agent_name") or "",
                    alert_id,
                )
                confidence_tag = a.get('confidence', 'HIGH')
                print(
                    f"[ALERT] {a.get('rule_id')} | "
                    f"{a.get('severity','').upper()} | "
                    f"conf={confidence_tag} | "
                    f"{a.get('summary')}",
                    flush=True,
                )
    except Exception as exc:
        print(f"[ERROR] detector failed for event rowid={rowid}: {exc}", flush=True)

    if new_offset:
        db.set_offset(new_offset)
    return True


def run(db: DB):
    # Import here so detector can be developed independently
    from detector import run_rules

    offset = db.get_offset()
    print(f"[INFO] Starting ingestor. archives_offset={offset}", flush=True)
    print(f"[INFO] Watching: {ARCHIVES_JSON}", flush=True)

    pending: queue.Queue[tuple[str, int]] = queue.Queue(maxsize=WRITE_QUEUE_MAX)
    stop = threading.Event()
    stats = {"ingested": 0, "last_prune": time.time()}

    def writer():
        while not stop.is_set():
            try:
                line, new_offset = pending.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                if process_line(db, line, new_offset, run_rules):
                    stats["ingested"] += 1
                    if stats["ingested"] % 100 == 0:
                        print(f"[INFO] Ingested {stats['ingested']} events so far. queue_depth={pending.qsize()}", flush=True)
                    if time.time() - stats["last_prune"] > 3600:
                        db.prune_old_telemetry()
                        stats["last_prune"] = time.time()
            finally:
                pending.task_done()

    worker = threading.Thread(target=writer, name="sqlite-writer", daemon=True)
    worker.start()

    for line, new_offset in tail_file(ARCHIVES_JSON, offset):
        if not line:
            continue
        pending.put((line, new_offset))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if not Path(SCHEMA_PATH).exists():
        print(f"[FATAL] schema.sql not found at {SCHEMA_PATH}")
        sys.exit(1)

    if MULTI_TENANT:
        print("[INFO] MULTI_TENANT=1 — SaaS routing mode active.", flush=True)
        # Initialise TenantManager early so cache is primed before first log arrives
        _get_tenant_manager()
    else:
        print("[INFO] MULTI_TENANT=0 — Single-tenant lab mode active.", flush=True)

    db = DB(EDR_DB_PATH)
    try:
        run(db)
    except KeyboardInterrupt:
        print("\n[INFO] Ingestor stopped.", flush=True)
