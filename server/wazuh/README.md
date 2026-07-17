# Wazuh

Docker Compose configuration for the local Wazuh Manager used by the lab.

## Files

| Path | Purpose |
|---|---|
| `docker-compose.yml` | Wazuh Manager service and volumes. |
| `config/` | Wazuh Manager, dashboard, indexer, and local lab certificate config. |

## Usage

Normally start through the root launcher:

```bat
START EDR.bat
```

Manual:

```powershell
cd server\wazuh
docker compose up -d
docker compose ps
docker compose down
```

The ingestor tails Wazuh archives through Docker using:

```text
/var/ossec/logs/archives/archives.json
```

