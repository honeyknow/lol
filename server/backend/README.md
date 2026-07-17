# Backend API

FastAPI backend for the ISHA-X EDR dashboard.

## Main File

| File | Purpose |
|---|---|
| `main.py` | API routes, DB access, evidence assembly, rules API, deployment helper routes. |
| `requirements.txt` | Backend Python dependencies. |
| `db_clear.py` | Utility to clear telemetry while preserving endpoint/agent metadata where present. |
| `db_clear_all.py` | Utility to clear all telemetry and endpoint/agent metadata. |

## Database

The backend resolves the canonical DB dynamically:

```text
server/pipeline/edr.db
```

It derives this path from `main.py`, so the project folder can move without editing DB paths.

## Important Routes

| Route | Purpose |
|---|---|
| `GET /health` | Pipeline and DB health. |
| `GET /stats` | Dashboard summary counts. |
| `GET /alerts` | Alert list. |
| `GET /alerts/{id}` | Single formatted alert. |
| `GET /alerts/{id}/evidence` | Evidence drawer payload. |
| `GET /rules` | Loaded Sigma/metadata rules. |
| `POST /rules/{id}/toggle` | Enable/disable rule UUID through `disabled_rules.json`. |
| `GET /amsi` | AMSI event list. |
| `GET /process-tree` | Process graph for a root process GUID. |
| `GET /timeline` | Event timeline for Firehose view. |

## Known Follow-Up

Phase 2 removed the old AI route and fixed the known `severity_score` schema drift. Remaining backend follow-up is live endpoint validation for all 8 scoped techniques and optional hardening for authentication if this lab is exposed beyond localhost/LAN.
