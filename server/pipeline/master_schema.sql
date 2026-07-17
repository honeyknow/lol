-- =============================================================================
-- ISHAX SaaS v2 — Master Database Schema
-- =============================================================================
-- Purpose: Acts as the central directory/router for multi-tenant operations.
--          Does NOT store EDR logs or alerts. Those live in per-tenant .db files.
--
-- Tables:
--   tenants   : Registered SaaS users (linked to Google email via JWT/OAuth)
--   agents    : Wazuh-registered agent IDs mapped to owning tenant
-- =============================================================================

PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;
PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------------
-- tenants
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenants (
    id           TEXT PRIMARY KEY,             -- UUID slug: e.g. "tenant_8f3a2b"
    email        TEXT UNIQUE NOT NULL,         -- Google email: "user@gmail.com"
    display_name TEXT,                         -- Optional display name
    db_filename  TEXT UNIQUE NOT NULL,         -- e.g. "tenant_8f3a2b.db"
    created_at   INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    last_login   INTEGER,
    is_active    INTEGER NOT NULL DEFAULT 1    -- 0 = banned/disabled
);

CREATE INDEX IF NOT EXISTS idx_tenants_email ON tenants(email);

-- ---------------------------------------------------------------------------
-- agents
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS agents (
    agent_id      TEXT PRIMARY KEY,            -- Wazuh-issued agent ID: "015"
    tenant_id     TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_name    TEXT,                        -- Human label: "Rahul-PC"
    registered_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    last_seen_at  INTEGER,
    is_revoked    INTEGER NOT NULL DEFAULT 0,  -- 1 = agent removed by user
    is_isolated   INTEGER NOT NULL DEFAULT 0   -- 1 = network isolated via Kill Switch
);

CREATE INDEX IF NOT EXISTS idx_agents_tenant   ON agents(tenant_id);
CREATE INDEX IF NOT EXISTS idx_agents_revoked  ON agents(is_revoked);
CREATE INDEX IF NOT EXISTS idx_agents_isolated ON agents(is_isolated);

-- ---------------------------------------------------------------------------
-- allowed_users
-- Whitelist of emails permitted to login (Email + Password auth).
-- Admin email (info.honeyknows@gmail.com) is ALWAYS allowed regardless.
-- Managed via Admin Panel UI — no code change or restart needed.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS allowed_users (
    email         TEXT PRIMARY KEY,                -- User email (lowercase)
    password_hash TEXT,                            -- bcrypt hash
    added_by      TEXT NOT NULL DEFAULT 'admin',   -- Who granted access
    added_at      INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    note          TEXT                             -- Optional label: "User 1 - Rahul"
);

-- Pre-seed the admin email so it always appears in the list (password checked via .env)
INSERT OR IGNORE INTO allowed_users (email, added_by, note)
VALUES ('info.honeyknows@gmail.com', 'system', 'Admin');

