#!/usr/bin/env python3
"""
ISHA-X EDR â€” sync_agents.py
============================
Called by start.sh after Wazuh Manager starts.

Problem it solves:
  When a Wazuh agent enrolls directly via port 1515 (auto-enrollment),
  it gets an agent_id from Wazuh (e.g. '004'), but the ISHA-X master.db
  phonebook doesn't know about it. The ingestor then DROPs every event
  from that agent with: "DROPPED: agent_id='004' not registered in master.db"

This script:
  1. Queries the Wazuh REST API for ALL registered agents.
  2. For each agent NOT already in master.db, inserts it linked to the
     admin tenant (first tenant in master.db).
  3. Logs every action clearly.

Usage:
  python3 sync_agents.py        (called automatically by start.sh)
"""

import os
import sqlite3
import sys
import json
from pathlib import Path

# ---------------------------------------------------------------------------
# Load .env from backend folder
# ---------------------------------------------------------------------------
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent.parent / "backend" / ".env"
    if env_path.exists():
        load_dotenv(dotenv_path=env_path)
        print(f"[sync_agents] Loaded .env from {env_path}", flush=True)
except ImportError:
    pass  # dotenv optional

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
WAZUH_API_BASE = os.getenv("WAZUH_API_BASE", "https://localhost:55000")
WAZUH_API_USER = os.getenv("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASS = os.getenv("WAZUH_API_PASS", "MyS3cr37P450r.*-")
MASTER_DB_PATH = Path(__file__).parent / "master.db"

# ---------------------------------------------------------------------------
# Wazuh API helpers
# ---------------------------------------------------------------------------
def get_wazuh_token() -> str:
    """Authenticate and return a JWT token from Wazuh API."""
    import urllib.request, base64, ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    creds = base64.b64encode(f"{WAZUH_API_USER}:{WAZUH_API_PASS}".encode()).decode()
    url = f"{WAZUH_API_BASE}/security/user/authenticate"
    req = urllib.request.Request(
        url,
        method="GET",
        headers={"Authorization": f"Basic {creds}"}
    )
    with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
        data = json.loads(resp.read())
        return data["data"]["token"]


def get_wazuh_agents(token: str) -> list[dict]:
    """Return list of all agents registered in Wazuh."""
    import urllib.request, ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    url = f"{WAZUH_API_BASE}/agents?limit=500&select=id,name,status"
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {token}"}
    )
    with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
        data = json.loads(resp.read())
        return data.get("data", {}).get("affected_items", [])


# ---------------------------------------------------------------------------
# master.db helpers
# ---------------------------------------------------------------------------
def get_master_con() -> sqlite3.Connection:
    con = sqlite3.connect(str(MASTER_DB_PATH), check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    return con


def get_admin_tenant_id(con: sqlite3.Connection) -> str | None:
    """Return the tenant_id of the first admin / active tenant."""
    row = con.execute(
        "SELECT id FROM tenants WHERE is_active = 1 ORDER BY created_at ASC LIMIT 1"
    ).fetchone()
    return row["id"] if row else None


def get_registered_agent_ids(con: sqlite3.Connection) -> set[str]:
    rows = con.execute("SELECT agent_id FROM agents WHERE is_revoked = 0").fetchall()
    return {row["agent_id"] for row in rows}


def register_agent(con: sqlite3.Connection, agent_id: str, agent_name: str, tenant_id: str):
    con.execute(
        "INSERT OR IGNORE INTO agents (agent_id, tenant_id, agent_name) VALUES (?, ?, ?)",
        (agent_id, tenant_id, agent_name),
    )
    con.commit()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    if not MASTER_DB_PATH.exists():
        print(f"[sync_agents] master.db not found at {MASTER_DB_PATH} â€” skipping sync", flush=True)
        return

    # Connect to master.db
    try:
        con = get_master_con()
    except Exception as e:
        print(f"[sync_agents] Cannot open master.db: {e}", flush=True)
        return

    # Get admin tenant
    admin_tenant = get_admin_tenant_id(con)
    if not admin_tenant:
        print("[sync_agents] No active tenant found in master.db â€” skipping sync", flush=True)
        print("[sync_agents] (User needs to log in at least once to create a tenant)", flush=True)
        con.close()
        return

    print(f"[sync_agents] Admin tenant: {admin_tenant}", flush=True)

    # Get already-registered agents
    registered = get_registered_agent_ids(con)
    print(f"[sync_agents] Already registered agent IDs: {registered or '{none}'}", flush=True)

    # Query Wazuh API
    try:
        token = get_wazuh_token()
        wazuh_agents = get_wazuh_agents(token)
        print(f"[sync_agents] Wazuh has {len(wazuh_agents)} agent(s)", flush=True)
    except Exception as e:
        print(f"[sync_agents] Wazuh API not reachable: {e}", flush=True)
        print("[sync_agents] Skipping sync â€” Wazuh may still be starting", flush=True)
        con.close()
        return

    # Sync: insert any missing agents
    synced = 0
    for agent in wazuh_agents:
        agent_id = str(agent.get("id", "")).zfill(3)  # normalize to 3 digits e.g. "004"
        agent_name = agent.get("name", agent_id)

        # Skip Wazuh's own manager node (ID 000)
        if agent_id == "000":
            continue

        if agent_id not in registered:
            register_agent(con, agent_id, agent_name, admin_tenant)
            print(f"[sync_agents] âœ… Registered agent {agent_id} ({agent_name}) â†’ tenant {admin_tenant}", flush=True)
            synced += 1
        else:
            print(f"[sync_agents] Agent {agent_id} ({agent_name}) already registered", flush=True)

    con.close()

    if synced == 0:
        print("[sync_agents] All Wazuh agents are already registered in master.db âœ“", flush=True)
    else:
        print(f"[sync_agents] Sync complete: {synced} new agent(s) registered", flush=True)


if __name__ == "__main__":
    main()


