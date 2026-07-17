# ISHA-X EDR

A cloud-hosted Endpoint Detection & Response system. Agents install on Windows endpoints and send telemetry to a GitHub Codespace running Wazuh + a custom FastAPI + React dashboard.

## Quick Start (Codespace)

1. **Fork** this repo and open in GitHub Codespaces.
2. Wait for `setup.sh` to finish (runs automatically — installs all prerequisites).
3. Open a terminal and authenticate Tailscale if prompted:
   ```bash
   sudo tailscale up
   ```
4. The stack starts automatically. Open the **Ports** tab → click port 8000.
5. From the Dashboard → **Download Agent** → install on Windows endpoints.

## First-time .env setup

```bash
cp server/backend/.env.example server/backend/.env
# Edit the file and fill in:
#   GROQ_API_KEY        — from console.groq.com
#   ADMIN_EMAILS        — your Google email
#   SESSION_SECRET      — random hex string
#   TAILSCALE_AUTH_KEY  — from login.tailscale.com/admin/settings/keys
nano server/backend/.env
```

Then run:
```bash
bash setup.sh   # install prereqs + configure
bash start.sh   # start full stack
```

## Architecture

```
Windows Endpoint
  └── Wazuh Agent (auto-installed)
        └──[Tailscale VPN]──► Codespace
                                 ├── Wazuh Manager (Docker) ← collects events
                                 ├── ingestor.py  ← parses + stores events
                                 ├── detector.py  ← Sigma rule matching → alerts
                                 └── FastAPI + React Dashboard (port 8000)
```

## Log files

| File | Purpose |
|------|---------|
| `logs/setup.log` | One-time setup output |
| `logs/start.log` | Stack startup |
| `logs/ingestor.log` | Live event pipeline |
| `logs/backend.log` | API requests & errors |
| `logs/wazuh.log` | Wazuh container |

## Troubleshooting

```bash
# Check all processes running
ps aux | grep -E "ingestor|uvicorn"

# Check ingestor for dropped events
grep "DROPPED" logs/ingestor.log

# Re-sync Wazuh agents into master.db
python3 server/pipeline/sync_agents.py

# Restart the full stack
bash start.sh
```
