#!/usr/bin/env python3
"""
ISHAX SaaS v2 — Multi-Tenant Manager
======================================
Central routing engine for the Database-Per-Tenant architecture.

Responsibilities:
  1. Open and maintain a connection to master.db (the phonebook).
  2. On first login: provision a new tenant (create UUID slug, initialise
     a fresh per-tenant .db file from schema.sql, write row to master.db).
  3. On agent registration: link a Wazuh agent_id to the owning tenant.
  4. On log ingestion: resolve agent_id → tenant db file path.
  5. Connection pooling: keep per-tenant connections in memory to avoid
     repeated open/close overhead on every log line.

Usage:
    from multi_tenant_manager import TenantManager
    mgr = TenantManager()

    # On user first login (called by FastAPI auth handler):
    tenant = mgr.ensure_tenant("rahul@gmail.com", display_name="Rahul")

    # On "Download Setup" click (called by /api/download-setup endpoint):
    agent_id = mgr.register_agent(tenant_id="tenant_8f3a2b", agent_name="Rahul-PC")

    # On each log line in ingestor.py:
    db_conn = mgr.get_tenant_db_by_agent("015")   # returns sqlite3.Connection or None
"""

import os
import sqlite3
import time
import uuid
from pathlib import Path
from threading import Lock
import hashlib
import bcrypt

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_HERE          = Path(__file__).parent
MASTER_DB_PATH = _HERE / "master.db"
MASTER_SCHEMA  = _HERE / "master_schema.sql"
TENANT_DB_DIR  = _HERE / "tenants"
TENANT_SCHEMA  = _HERE / "schema.sql"


class TenantManager:
    """
    Thread-safe manager for multi-tenant SQLite routing.

    master.db  = the phonebook (tenants + agents tables)
    tenants/   = one .db file per registered user
    """

    def __init__(self):
        TENANT_DB_DIR.mkdir(exist_ok=True)
        self._master: sqlite3.Connection = self._open_master()
        # In-memory connection pool:  { tenant_id -> sqlite3.Connection }
        self._pool: dict[str, sqlite3.Connection] = {}
        # Cache: { agent_id -> tenant_id } to avoid master.db lookup on every log line
        self._agent_cache: dict[str, str] = {}
        self._lock = Lock()
        self._prime_cache()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _open_master(self) -> sqlite3.Connection:
        con = sqlite3.connect(str(MASTER_DB_PATH), check_same_thread=False)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
        con.execute("PRAGMA foreign_keys=ON")
        if MASTER_SCHEMA.exists():
            con.executescript(MASTER_SCHEMA.read_text())
            
        # Migration: Add password_hash if it doesn't exist
        try:
            con.execute("ALTER TABLE allowed_users ADD COLUMN password_hash TEXT")
        except sqlite3.OperationalError:
            pass # Column already exists
            
        con.commit()
        print(f"[TenantManager] master.db opened at {MASTER_DB_PATH}", flush=True)
        return con

    def _open_tenant_db(self, db_filename: str) -> sqlite3.Connection:
        """Open (or create + initialise) a tenant .db file."""
        db_path = TENANT_DB_DIR / db_filename
        con = sqlite3.connect(str(db_path), check_same_thread=False)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
        con.execute("PRAGMA busy_timeout=5000")
        con.execute("PRAGMA foreign_keys=ON")
        # Initialise schema if the file is brand new
        if TENANT_SCHEMA.exists():
            con.executescript(TENANT_SCHEMA.read_text())
        con.commit()
        return con

    def _prime_cache(self):
        """Load all active (non-revoked) agent→tenant mappings into memory."""
        rows = self._master.execute(
            "SELECT agent_id, tenant_id FROM agents WHERE is_revoked = 0"
        ).fetchall()
        for row in rows:
            self._agent_cache[row["agent_id"]] = row["tenant_id"]
        print(
            f"[TenantManager] Agent cache primed: {len(self._agent_cache)} entries",
            flush=True,
        )

    # ------------------------------------------------------------------
    # Public API — Tenant provisioning
    # ------------------------------------------------------------------

    def ensure_tenant(self, email: str, display_name: str = "") -> dict:
        """
        Called when a user logs in.
        If the email is already registered, returns the existing tenant row.
        If new, creates a UUID slug, a fresh .db file, and a master.db row.

        Returns: dict with keys: id, email, db_filename, is_active
        """
        with self._lock:
            row = self._master.execute(
                "SELECT * FROM tenants WHERE email = ?", (email,)
            ).fetchone()
            if row:
                # Update last_login
                self._master.execute(
                    "UPDATE tenants SET last_login = ? WHERE email = ?",
                    (int(time.time()), email),
                )
                self._master.commit()
                return dict(row)

            # New user — generate slug
            slug = "tenant_" + uuid.uuid4().hex[:8]
            db_filename = slug + ".db"

            # Pre-initialise the tenant .db file (applies schema.sql)
            con = self._open_tenant_db(db_filename)
            self._pool[slug] = con

            self._master.execute(
                """
                INSERT INTO tenants (id, email, display_name, db_filename, last_login)
                VALUES (?, ?, ?, ?, ?)
                """,
                (slug, email, display_name or email.split("@")[0], db_filename, int(time.time())),
            )
            self._master.commit()
            print(f"[TenantManager] New tenant provisioned: {email} -> {db_filename}", flush=True)
            row = self._master.execute(
                "SELECT * FROM tenants WHERE id = ?", (slug,)
            ).fetchone()
            return dict(row)

    def get_tenant_by_email(self, email: str) -> dict | None:
        """Return tenant row dict or None."""
        row = self._master.execute(
            "SELECT * FROM tenants WHERE email = ? AND is_active = 1", (email,)
        ).fetchone()
        return dict(row) if row else None

    def get_all_tenants(self) -> list[dict]:
        """Admin only: return all registered tenants."""
        rows = self._master.execute(
            "SELECT * FROM tenants ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def deactivate_tenant(self, tenant_id: str):
        """Admin: ban a tenant without deleting their data."""
        with self._lock:
            self._master.execute(
                "UPDATE tenants SET is_active = 0 WHERE id = ?", (tenant_id,)
            )
            self._master.commit()

    def purge_tenant(self, tenant_id: str):
        """Admin: permanently delete a tenant and their .db file."""
        with self._lock:
            row = self._master.execute(
                "SELECT db_filename FROM tenants WHERE id = ?", (tenant_id,)
            ).fetchone()
            if row:
                db_path = TENANT_DB_DIR / row["db_filename"]
                # Close pooled connection first
                con = self._pool.pop(tenant_id, None)
                if con:
                    con.close()
                if db_path.exists():
                    db_path.unlink()
            # Cascade deletes agents rows too (FK ON DELETE CASCADE)
            self._master.execute("DELETE FROM tenants WHERE id = ?", (tenant_id,))
            self._master.commit()
            # Evict from agent cache
            evict = [aid for aid, tid in self._agent_cache.items() if tid == tenant_id]
            for aid in evict:
                del self._agent_cache[aid]
            print(f"[TenantManager] Tenant {tenant_id} purged.", flush=True)

    # ------------------------------------------------------------------
    # Public API — Agent management
    # ------------------------------------------------------------------

    def register_agent(self, tenant_id: str, agent_id: str, agent_name: str = "") -> dict:
        """
        Link a Wazuh agent_id to a tenant.
        Called by the FastAPI /api/download-setup endpoint after pre-registering
        the agent with the Wazuh Manager API.

        Returns the new agents row as a dict.
        """
        with self._lock:
            existing = self._master.execute(
                "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()
            if existing:
                return dict(existing)
            self._master.execute(
                """
                INSERT INTO agents (agent_id, tenant_id, agent_name)
                VALUES (?, ?, ?)
                """,
                (agent_id, tenant_id, agent_name or agent_id),
            )
            self._master.commit()
            self._agent_cache[agent_id] = tenant_id
            print(
                f"[TenantManager] Agent registered: {agent_id} → tenant {tenant_id}",
                flush=True,
            )
            return dict(
                self._master.execute(
                    "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
                ).fetchone()
            )

    def revoke_agent(self, agent_id: str, requesting_tenant_id: str) -> bool:
        """
        Mark an agent as revoked. Returns True on success, False if the
        requesting tenant doesn't own the agent (prevents cross-tenant abuse).
        """
        with self._lock:
            row = self._master.execute(
                "SELECT tenant_id FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()
            if not row:
                return False
            if row["tenant_id"] != requesting_tenant_id:
                return False  # 403 — not your agent
            self._master.execute(
                "UPDATE agents SET is_revoked = 1 WHERE agent_id = ?", (agent_id,)
            )
            self._master.commit()
            self._agent_cache.pop(agent_id, None)
            return True

    def get_agents_for_tenant(self, tenant_id: str) -> list[dict]:
        """Return all (non-revoked) agents owned by a tenant."""
        rows = self._master.execute(
            """
            SELECT * FROM agents
            WHERE tenant_id = ? AND is_revoked = 0
            ORDER BY registered_at DESC
            """,
            (tenant_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def update_agent_last_seen(self, agent_id: str):
        """Called by ingestor.py whenever a log from this agent is ingested."""
        self._master.execute(
            "UPDATE agents SET last_seen_at = ? WHERE agent_id = ?",
            (int(time.time()), agent_id),
        )
        # Commit is batched — caller should commit master periodically

    # ------------------------------------------------------------------
    # Public API — Connection routing (used by ingestor.py)
    # ------------------------------------------------------------------

    def get_tenant_db_by_agent(self, agent_id: str) -> sqlite3.Connection | None:
        """
        Main routing method called on every log line.
        1. Look up tenant_id in the fast in-memory cache.
        2. Return (or open) a pooled sqlite3.Connection for that tenant's .db.
        Returns None if the agent_id is unknown / revoked.
        """
        tenant_id = self._agent_cache.get(agent_id)
        if not tenant_id:
            # Cache miss — try master.db (handles hot-added agents)
            row = self._master.execute(
                "SELECT tenant_id FROM agents WHERE agent_id = ? AND is_revoked = 0",
                (agent_id,),
            ).fetchone()
            if not row:
                return None
            tenant_id = row["tenant_id"]
            self._agent_cache[agent_id] = tenant_id

        return self._get_pooled_connection(tenant_id)

    def get_tenant_db_by_id(self, tenant_id: str) -> sqlite3.Connection | None:
        """
        Used by the FastAPI dashboard endpoints to open the right .db
        for the requesting user (or for admin impersonation).
        """
        return self._get_pooled_connection(tenant_id)

    def _get_pooled_connection(self, tenant_id: str) -> sqlite3.Connection | None:
        with self._lock:
            if tenant_id in self._pool:
                return self._pool[tenant_id]
            # Pool miss — look up db_filename and open it
            row = self._master.execute(
                "SELECT db_filename FROM tenants WHERE id = ? AND is_active = 1",
                (tenant_id,),
            ).fetchone()
            if not row:
                return None
            con = self._open_tenant_db(row["db_filename"])
            self._pool[tenant_id] = con
            return con

    # ------------------------------------------------------------------
    # Public API — Admin helpers
    # ------------------------------------------------------------------

    def get_tenant_db_size_bytes(self, tenant_id: str) -> int:
        """Return the file size in bytes of a tenant's .db file."""
        row = self._master.execute(
            "SELECT db_filename FROM tenants WHERE id = ?", (tenant_id,)
        ).fetchone()
        if not row:
            return 0
        path = TENANT_DB_DIR / row["db_filename"]
        return path.stat().st_size if path.exists() else 0

    def get_all_tenants_with_stats(self) -> list[dict]:
        """Admin: tenants + agent count + db size."""
        tenants = self.get_all_tenants()
        result = []
        for t in tenants:
            agent_count = self._master.execute(
                "SELECT COUNT(*) FROM agents WHERE tenant_id = ? AND is_revoked = 0",
                (t["id"],),
            ).fetchone()[0]
            result.append({
                **t,
                "agent_count": agent_count,
                "db_size_bytes": self.get_tenant_db_size_bytes(t["id"]),
            })
        return result

    # ------------------------------------------------------------------
    # Public API — Allowed-user whitelist (replaces ALLOWED_EMAILS env var)
    # ------------------------------------------------------------------

    def is_email_allowed(self, email: str) -> bool:
        """
        Check if an email is in the whitelist.
        The super-admin email is always allowed regardless.
        """
        email = email.strip().lower()
        if email == "info.honeyknows@gmail.com":
            return True
        row = self._master.execute(
            "SELECT 1 FROM allowed_users WHERE email = ?", (email,)
        ).fetchone()
        return row is not None

    def get_allowed_users(self) -> list[dict]:
        """Return all whitelisted emails with metadata."""
        rows = self._master.execute(
            "SELECT email, added_by, added_at, note FROM allowed_users ORDER BY added_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def add_allowed_user(self, email: str, password: str = "", added_by: str = "admin", note: str = "") -> dict:
        """
        Add an email to the whitelist.
        Returns the new row dict.
        Raises ValueError if email already exists.
        """
        email = email.strip().lower()
        if not email or "@" not in email:
            raise ValueError(f"Invalid email: {email!r}")
            
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode() if password else ""
        
        with self._lock:
            existing = self._master.execute(
                "SELECT email FROM allowed_users WHERE email = ?", (email,)
            ).fetchone()
            if existing:
                raise ValueError(f"{email} is already whitelisted.")
            self._master.execute(
                "INSERT INTO allowed_users (email, password_hash, added_by, note) VALUES (?, ?, ?, ?)",
                (email, password_hash, added_by, note or ""),
            )
            self._master.commit()
            print(f"[TenantManager] Allowed user added: {email} (by {added_by})", flush=True)
        return {"email": email, "added_by": added_by, "note": note}

    def verify_user_password(self, email: str, password: str) -> bool:
        """Verify the password of an allowed user."""
        email = email.strip().lower()
        row = self._master.execute(
            "SELECT password_hash FROM allowed_users WHERE email = ?", (email,)
        ).fetchone()
        
        if not row or not row["password_hash"]:
            return False
        try:
            return bcrypt.checkpw(password.encode(), row["password_hash"].encode())
        except Exception:
            return False

    def remove_allowed_user(self, email: str) -> bool:
        """
        Remove an email from the whitelist.
        Returns False if the email is the super-admin (cannot be removed) or not found.
        """
        email = email.strip().lower()
        if email == "info.honeyknows@gmail.com":
            return False  # Super-admin is permanent
        with self._lock:
            cur = self._master.execute(
                "DELETE FROM allowed_users WHERE email = ?", (email,)
            )
            self._master.commit()
        return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Module-level singleton — import this in ingestor.py and main.py
# ---------------------------------------------------------------------------
_manager_instance: TenantManager | None = None


def get_manager() -> TenantManager:
    """Return the module-level singleton TenantManager."""
    global _manager_instance
    if _manager_instance is None:
        _manager_instance = TenantManager()
    return _manager_instance
