# Frontend Dashboard

React/Vite dashboard for the ISHA-X EDR lab.

## Views

| View | Purpose |
|---|---|
| Overview | Health, counts, hosts, and recent alerts. |
| Threat Hunt | Process tree, evidence drawer, incident chains, and blast radius views. |
| Firehose | Timeline-style event stream. |
| Rules Engine | Rule inventory and enable/disable toggles. |

## Development

```powershell
npm install
npm run dev
npm run lint
```

The Vite proxy sends `/api/*` to the backend. By default it uses:

```text
http://localhost:8000
```

`server/start_local.ps1` can override that through `VITE_API_TARGET`.

## Key Paths

| Path | Purpose |
|---|---|
| `src/api/client.ts` | Typed API client. |
| `src/pages/` | Top-level dashboard pages. |
| `src/components/` | Reusable analyst UI components. |
| `src/assets/` | Static UI assets. |

