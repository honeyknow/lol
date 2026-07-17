# Pipeline

The pipeline is the detection core of the project.

## Files

| File/folder | Purpose |
|---|---|
| `schema.sql` | SQLite schema for events, detections, alerts, graph, and threat intel tables. |
| `DB_README.md` | Field-level database guide: sources, consumers, missing-data cases, and suggested fixes. |
| `ingestor.py` | Tails Wazuh `archives.json`, normalizes fields, writes events, calls detector. |
| `detector.py` | AMSI pattern matching, pySigma SQLite matching, raw detection staging, merge logic. |
| `sigma_rules/` | YAML detection rules for the locked scope. |
| `disabled_rules.json` | Runtime rule disable list. |
| `migrate_db.py` | Dynamic-path migration helper for GUID and AMSI payload normalization. |
| `migrate_rules.py` | Mirrors YAML rule metadata into the SQLite `rules` table. |
| `verify_phase1.py` | Evidence/rules verification helper. |
| `threat_intel_worker.py` | Enrichment worker for queued indicators. |

## Pipeline Flow

```text
archives.json
  -> ingestor.normalise()
  -> events table
  -> detector.run_rules()
  -> raw_detections
  -> detector._run_merge()
  -> alerts
  -> alert_event_links / process graph
```

## Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `ARCHIVES_JSON` | `/var/ossec/logs/archives/archives.json` | Source file, or `docker` for docker exec tailing. |
| `EDR_DB_PATH` | `server/pipeline/edr.db` | SQLite database path. |
| `POLL_INTERVAL` | `0.5` | Tail polling interval. |
| `EDR_SOURCE_TYPE` | auto | Override endpoint source type. |
| `EDR_RETENTION_DAYS` | `14` | Prune window for unlinked telemetry. |
