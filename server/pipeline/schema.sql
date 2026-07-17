-- =============================================================================
-- ISHAX v2 — SQLite Schema (rebuilt 2026-07-11)
-- =============================================================================
-- Tables:
--   events           : Normalised raw events from Wazuh archives.json
--   raw_detections   : Staging table for dual-layer merge (§3)
--   alerts           : Final merged detection records with confidence scoring
--   alert_event_links: M:M alerts↔events
--   process_nodes    : Process tree nodes (Sysmon EID 1/5)
--   process_edges    : Process activity edges (net/file/registry)
--   threat_intel_*   : VT lookup queue and cache
--   ingestion_state  : Tail-file byte offset
-- =============================================================================

PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 5000;
PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------------
-- events
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Wazuh envelope
    wazuh_id        TEXT    UNIQUE NOT NULL,
    wazuh_ts        TEXT    NOT NULL,
    wazuh_ts_epoch  INTEGER NOT NULL,

    -- Agent
    agent_id        TEXT,
    agent_name      TEXT,
    agent_ip        TEXT,
    endpoint_id     TEXT,
    event_source    TEXT,
    technique_candidate TEXT,
    source_type     TEXT    NOT NULL DEFAULT 'endpoint',

    -- Windows Event core
    channel         TEXT,
    event_id        INTEGER,
    provider_name   TEXT,
    computer        TEXT,

    -- Normalised eventdata
    subject_user    TEXT,
    target_user     TEXT,
    logon_type      TEXT,
    service_name    TEXT,
    image_path      TEXT,
    command_line    TEXT,
    parent_image    TEXT,
    parent_command_line TEXT,
    process_guid    TEXT,
    parent_process_guid TEXT,
    source_image    TEXT,
    target_image    TEXT,
    granted_access  TEXT,
    destination_ip  TEXT,
    destination_port TEXT,
    target_filename TEXT,
    hashes          TEXT,
    target_object   TEXT,
    details         TEXT,
    ticket_options  TEXT,
    ticket_enc_type TEXT,
    access_mask     TEXT,
    properties      TEXT,
    original_file_name TEXT,
    service_binary_path TEXT,
    service_start_delta_seconds INTEGER,
    command_line_flags TEXT,
    registry_path   TEXT,
    process_hash    TEXT,
    process_path    TEXT,
    source_ip       TEXT,
    username        TEXT,
    call_trace      TEXT,     -- Sysmon EID 10: CallTrace (stack trace for process access, e.g. comsvcs.dll)
    -- AMSI fields (populated for ISHAX-AMSI channel events)
    amsi_scan_result    INTEGER,  -- 0=clean, 1=not_detected, 32768=detected
    amsi_content_name   TEXT,     -- ContentName from AMSI ETW (e.g. "PowerShell_C:\...")
    amsi_content_hex    TEXT,     -- Content buffer as hex (UTF-16LE, decode before matching)

    raw_json_original   TEXT    NOT NULL,
    raw_json_normalized TEXT    NOT NULL,
    raw_json        TEXT    NOT NULL,
    ingested_at     INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE INDEX IF NOT EXISTS idx_events_event_id     ON events(event_id);
CREATE INDEX IF NOT EXISTS idx_events_channel      ON events(channel);
CREATE INDEX IF NOT EXISTS idx_events_agent        ON events(agent_name);
CREATE INDEX IF NOT EXISTS idx_events_source_type  ON events(source_type);
CREATE INDEX IF NOT EXISTS idx_events_ts_epoch     ON events(wazuh_ts_epoch);
CREATE INDEX IF NOT EXISTS idx_events_target_user  ON events(target_user);
CREATE INDEX IF NOT EXISTS idx_events_image_path   ON events(image_path);
CREATE INDEX IF NOT EXISTS idx_events_process_guid ON events(process_guid);
CREATE INDEX IF NOT EXISTS idx_events_dest_ip      ON events(destination_ip);
CREATE INDEX IF NOT EXISTS idx_events_hashes       ON events(hashes);
CREATE INDEX IF NOT EXISTS idx_events_amsi_result  ON events(amsi_scan_result);

-- ---------------------------------------------------------------------------
-- raw_detections  (§3 dual-layer staging table)
-- ---------------------------------------------------------------------------
-- Each potential detection (AMSI Layer A OR Sigma Layer B) is inserted here
-- before merge. The merge logic reads ±30s windows by (technique, process_guid,
-- endpoint_id) to determine confidence and emit exactly one alert per group.
-- merged=1 rows have already been promoted to alerts; skip in future runs.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS raw_detections (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    process_guid    TEXT,
    endpoint_id     TEXT,
    ts              INTEGER NOT NULL,
    layer           TEXT    NOT NULL CHECK(layer IN ('amsi','cmdline','service','registry')),
    technique       TEXT    NOT NULL,     -- T1059.001, T1059.005, etc.
    matched_pattern TEXT,
    obfuscation_score REAL  DEFAULT 0.0, -- T1027 score [0.0, 1.0] from AMSI content
    event_id_fk     INTEGER REFERENCES events(id) ON DELETE CASCADE,
    merged          INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    -- Unique per (event row, layer, technique) — prevents double-insert on retry
    UNIQUE(event_id_fk, layer, technique)
);
CREATE INDEX IF NOT EXISTS idx_rd_technique_guid ON raw_detections(technique, process_guid);
CREATE INDEX IF NOT EXISTS idx_rd_ts             ON raw_detections(ts);
CREATE INDEX IF NOT EXISTS idx_rd_merged         ON raw_detections(merged);

-- ---------------------------------------------------------------------------
-- alerts
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    fired_at        INTEGER NOT NULL DEFAULT (strftime('%s','now')),

    rule_id         TEXT    NOT NULL,
    rule_name       TEXT    NOT NULL,
    mitre_technique TEXT    NOT NULL,
    severity        TEXT    NOT NULL CHECK(severity IN ('low','medium','high','critical')),

    -- Source event
    event_id_fk     INTEGER REFERENCES events(id) ON DELETE CASCADE,
    wazuh_event_id  TEXT,
    source_process_guid TEXT,
    source_agent_name TEXT,
    source_type     TEXT,
    source_channel  TEXT,
    source_event_id INTEGER,
    source_wazuh_ts_epoch INTEGER,

    summary         TEXT    NOT NULL,
    matched_json    TEXT,

    -- v2 fields: dual-layer confidence (§3) + obfuscation overlay (§5)
    confidence              TEXT    DEFAULT 'HIGH' CHECK(confidence IN ('HIGH','MEDIUM','LOW')),
    amsi_matched_patterns   TEXT,   -- comma-sep list of AMSI content patterns that matched
    no_amsi_corroboration   INTEGER DEFAULT 0, -- 1 = cmdline fired but no AMSI within 30s window
    obfuscation_score       REAL    DEFAULT 0.0 -- T1027: [0.0,1.0]; >=0.5 = high obfuscation
);

CREATE INDEX IF NOT EXISTS idx_alerts_fired_at      ON alerts(fired_at);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id       ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity      ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_source_agent  ON alerts(source_agent_name);
CREATE INDEX IF NOT EXISTS idx_alerts_source_type   ON alerts(source_type);
CREATE INDEX IF NOT EXISTS idx_alerts_source_process ON alerts(source_process_guid);
CREATE INDEX IF NOT EXISTS idx_alerts_technique     ON alerts(mitre_technique);
CREATE INDEX IF NOT EXISTS idx_alerts_confidence    ON alerts(confidence);

-- ---------------------------------------------------------------------------
-- alert_event_links
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alert_event_links (
    alert_id        INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    event_id        INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    link_reason     TEXT    NOT NULL,
    PRIMARY KEY(alert_id, event_id, link_reason)
);
CREATE INDEX IF NOT EXISTS idx_alert_event_links_event ON alert_event_links(event_id);

-- ---------------------------------------------------------------------------
-- ingestion_state
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ingestion_state (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL
);
INSERT OR IGNORE INTO ingestion_state(key, value) VALUES ('archives_offset', '0');

-- ---------------------------------------------------------------------------
-- process_nodes / edges
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS process_nodes (
    process_guid        TEXT PRIMARY KEY,
    parent_process_guid TEXT,
    pid                 INTEGER,
    image               TEXT,
    command_line        TEXT,
    user_name           TEXT,
    host_id             TEXT,
    start_time          TEXT,
    end_time            TEXT
);
CREATE INDEX IF NOT EXISTS idx_process_nodes_parent ON process_nodes(parent_process_guid);
CREATE INDEX IF NOT EXISTS idx_process_nodes_start  ON process_nodes(start_time);
CREATE INDEX IF NOT EXISTS idx_process_nodes_pid    ON process_nodes(pid);
CREATE INDEX IF NOT EXISTS idx_process_nodes_host   ON process_nodes(host_id);

CREATE TABLE IF NOT EXISTS process_edges (
    process_guid    TEXT    NOT NULL,
    host_id         TEXT,
    edge_type       TEXT    NOT NULL,
    target_label    TEXT    NOT NULL,
    timestamp       TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_process_edges_guid      ON process_edges(process_guid);
CREATE INDEX IF NOT EXISTS idx_process_edges_guid_type ON process_edges(process_guid, edge_type);
CREATE INDEX IF NOT EXISTS idx_process_edges_host      ON process_edges(host_id);

-- ---------------------------------------------------------------------------
-- threat_intel
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS threat_intel_cache (
    indicator       TEXT    PRIMARY KEY,
    indicator_type  TEXT    NOT NULL CHECK(indicator_type IN ('sha256','ip')),
    provider        TEXT    NOT NULL DEFAULT 'virustotal',
    verdict         TEXT,
    score           INTEGER,
    raw_json        TEXT,
    checked_at      INTEGER NOT NULL,
    stale_after     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ti_cache_stale ON threat_intel_cache(stale_after);

CREATE TABLE IF NOT EXISTS threat_intel_queue (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id        INTEGER REFERENCES alerts(id) ON DELETE CASCADE,
    indicator       TEXT    NOT NULL,
    indicator_type  TEXT    NOT NULL CHECK(indicator_type IN ('sha256','ip')),
    status          TEXT    NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','done','error')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_run_at     INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    last_error      TEXT,
    created_at      INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    updated_at      INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    UNIQUE(alert_id, indicator, indicator_type)
);
CREATE INDEX IF NOT EXISTS idx_ti_queue_status_next ON threat_intel_queue(status, next_run_at);

-- ---------------------------------------------------------------------------
-- rules
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS rules (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT,
    mitre_technique TEXT,
    severity        TEXT,
    yaml_content    TEXT NOT NULL,
    enabled         INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);

-- ---------------------------------------------------------------------------
-- active_detections  (M-3 Fix: SQLite-backed upgrade tracker)
-- ---------------------------------------------------------------------------
-- Replaces in-memory _active_detections dict. Persists across restarts.
-- Allows MEDIUM→HIGH upgrade even if ingestor restarted between cmdline
-- detection and AMSI corroboration arriving (within the 30s merge window).
-- expires_at = ts + _ACTIVE_TTL (120s) — auto-excluded by queries after TTL.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS active_detections (
    technique       TEXT    NOT NULL,
    process_guid    TEXT    NOT NULL DEFAULT '',
    endpoint_id     TEXT    NOT NULL DEFAULT '',
    alert_id        INTEGER REFERENCES alerts(id) ON DELETE CASCADE,
    ts              INTEGER NOT NULL,
    confidence      TEXT    NOT NULL CHECK(confidence IN ('HIGH','MEDIUM')),
    expires_at      INTEGER NOT NULL,  -- strftime('%s','now') + TTL
    PRIMARY KEY (technique, process_guid, endpoint_id)
);
CREATE INDEX IF NOT EXISTS idx_ad_expires ON active_detections(expires_at);
