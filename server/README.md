# Server Folder

This folder contains the local EDR lab server stack.

## Components

| Path | Purpose |
|---|---|
| `start_local.ps1` | Starts/stops/checks Wazuh, ingestor, backend, and frontend. |
| `wazuh/` | Docker Compose Wazuh Manager configuration. |
| `pipeline/` | SQLite schema, Wazuh ingestor, detector, Sigma rules, and migrations. |
| `backend/` | FastAPI API over the SQLite database. |
| `frontend/` | React/Vite analyst dashboard. |

## Commands

From the project root:

```bat
START EDR.bat
STOP EDR.bat
```

Direct PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File server\start_local.ps1
powershell -ExecutionPolicy Bypass -File server\start_local.ps1 -Status
powershell -ExecutionPolicy Bypass -File server\start_local.ps1 -Stop
```

## Ports

| Port | Component |
|---:|---|
| 5173 | Vite dashboard |
| 8000 | FastAPI backend |
| 1514 | Wazuh event forwarding |
| 55000 | Wazuh API |

