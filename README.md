# CPS Threat Intelligence Dashboard v2.0

IT/OT threat detection for cyber-physical data center systems.
**GWU SEAS 8499 — Doctoral Practicum**

## Stack

| Layer | Technology |
|-------|-----------|
| Backend | Go 1.22 + Gin + GORM + SQLite |
| Frontend | React 18 + TypeScript + Vite |
| State | Zustand (client) + SQLite (server) |
| Charts | Chart.js + D3.js |
| Real-time | WebSocket (gorilla/websocket) |

## Project Structure

```
cps-dashboard/
├── backend/           # Go API server
│   ├── main.go
│   ├── internal/
│   │   ├── api/       # HTTP handlers (threats, mitre, actors, ml, ws...)
│   │   ├── db/        # SQLite connection + seed from JSON
│   │   ├── models/    # GORM data models
│   │   └── cache/     # TTL in-memory cache
│   └── data/          # JSON seed files (threats, actors, mitre...)
├── frontend/          # React + TypeScript
│   ├── src/
│   │   ├── pages/     # One component per dashboard tab (18 pages)
│   │   ├── components/# Sidebar, Header, LoadingSpinner, ErrorMessage
│   │   ├── services/  # API client (api.ts)
│   │   ├── store/     # Zustand global state (dashboard.ts)
│   │   └── types/     # TypeScript interfaces
│   └── vite.config.ts # Proxy /api → :8001, /ws → ws://:8001
└── start.sh           # Start both services
```

## Quickstart

```bash
# Start both services
./start.sh

# Or manually:
cd backend && go run .          # API on :8001
cd frontend && npm run dev      # UI  on :3000
```

Open **http://localhost:3000**

## Environment Variables

Copy `.env.example` to `backend/.env`:

```
ANTHROPIC_API_KEY=sk-ant-...   # AI Briefing tab
OTX_API_KEY=...                 # AlienVault OTX (optional)
PORT=8001
DATA_DIR=./data
DB_PATH=cps_dashboard.db
```

## Features

- **18 dashboard tabs** — Overview, MITRE ATT&CK ICS, Attack Scenarios, Threat Correlation,
  Physical Threats, Live Intel (CISA KEV + NVD), Threat Feed (WebSocket), Threat Actors,
  Security News, AI Briefing, ML-SOAR, ATT&CK Heatmap, Network Graph, Geo Risk Map,
  Kill Chain Builder, CVE Asset Map, Datasets, References
- **SQLite persistence** — threats, actors, incidents, geo risk, network graph seeded from JSON
- **Real-time WebSocket** — live threat event stream, critical events persisted to DB
- **ML-SOAR** — synthetic SWAT sensor anomaly detection with ROC curve + MTTD comparison
- **AI Briefing** — Claude-powered threat briefing (requires ANTHROPIC_API_KEY)
