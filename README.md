# Z3RODAY — CyberShark Security Dashboard

> **ICS/OT Threat Intelligence Platform**
> GWU SEAS 8499 — Doctoral Practicum

A full-stack cyber threat intelligence dashboard purpose-built for IT/OT and cyber-physical systems security research. Real-time threat feeds, MITRE ATT&CK ICS mapping, ML-SOAR analytics, nation-state actor intelligence, and an AI-powered briefing engine — all in a single operator interface.

---

## Stack

| Layer | Technology |
|---|---|
| Backend | Go 1.22 · Gin · GORM · SQLite |
| Frontend | React 18 · TypeScript · Vite |
| State | Zustand · SQLite |
| Visualization | Chart.js · D3.js |
| Real-time | WebSocket (gorilla/websocket) · SSE |
| AI | Anthropic Claude API (streaming) |

---

## Quickstart

```bash
# Clone
git clone https://github.com/Cybershark777/Z3RODAY_0.git
cd Z3RODAY_0

# Configure environment
cp backend/.env.example backend/.env
# Edit backend/.env — add ANTHROPIC_API_KEY for AI Briefing

# Start both services
./start.sh
```

Open **http://localhost:3000**

**Manual start:**
```bash
cd backend && go run ./cmd/server/main.go   # API on :8001
cd frontend && npm install && npm run dev   # UI  on :3000
```

---

## Environment Variables

`backend/.env`:

```env
ANTHROPIC_API_KEY=sk-ant-...      # AI Briefing (streaming Claude)
OTX_API_KEY=...                    # AlienVault OTX (optional)
GREYNOISE_API_KEY=...              # GreyNoise live data (optional)
SHODAN_API_KEY=...                 # Shodan live ICS data (optional)
PORT=8001
DATA_DIR=./data
DB_PATH=cps_dashboard.db
```

---

## Project Structure

```
Z3RODAY_0/
├── backend/
│   ├── cmd/server/main.go
│   ├── internal/
│   │   ├── api/          # HTTP handlers
│   │   │   ├── actors.go        # Threat actor intelligence + enrichment
│   │   │   ├── analytics.go     # ML-SOAR, CVE asset map, kill chain
│   │   │   ├── live.go          # CISA KEV, NVD, OTX, news, AI briefing/SSE
│   │   │   ├── mitre.go         # ATT&CK ICS tactics/techniques/heatmap
│   │   │   ├── threats.go       # Threat catalog + metrics
│   │   │   ├── threatintel.go   # ThreatFox, Feodo, URLhaus, MalwareBazaar, GreyNoise, Shodan, IOC search
│   │   │   ├── ws.go            # WebSocket live threat feed
│   │   │   └── router.go
│   │   ├── db/           # SQLite init + JSON seed
│   │   ├── models/       # GORM models
│   │   └── cache/        # TTL in-memory cache
│   └── data/             # JSON seed files
│       ├── threats.json         # 20+ ICS threat classes
│       ├── threat_actors.json   # 12 nation-state/criminal APT profiles
│       ├── mitre_ics.json       # Full ATT&CK for ICS matrix
│       └── ...
├── frontend/
│   └── src/
│       ├── pages/         # 19 dashboard pages
│       ├── components/    # Header, Sidebar, ThreatTicker, CriticalAlert
│       ├── services/      # api.ts — typed API client
│       ├── store/         # Zustand global state
│       └── styles/        # globals.css — dark theme with CSS variables
└── start.sh
```

---

## Dashboard Pages

| Tab | Description |
|---|---|
| **Overview** | Risk gauge, MTTD/MTTR metrics, attack timeline, threat table, CSV export |
| **MITRE ATT&CK ICS** | Full technique matrix with actor attribution counts, search, clickable MITRE links |
| **Attack Scenarios** | IT→OT kill chain scenarios traversing the Purdue Reference Model |
| **Threat Correlation** | Jaccard similarity matrix across threat classes by shared techniques |
| **IR Playbooks** | Step-by-step incident response for Grid Attack, Ransomware in OT, SIS Compromise, APT Recon |
| **Live Intel** | Global IOC search (ThreatFox+GreyNoise+Feodo+MalwareBazaar+KEV), CISA KEV, NVD CVE lookup |
| **Threat Feed** | Real-time WebSocket event stream |
| **Threat Actors** | 12 APT profiles — Sandworm, Volt Typhoon, TRITON, Lazarus, APT33/34/40, CHERNOVITE + more |
| **Security News** | Aggregated ICS/OT security news (CISA, ICS-CERT RSS) |
| **AI Briefing** | Streaming Claude-powered threat briefing (token-by-token SSE) |
| **ML-SOAR** | SWAT dataset anomaly detection, ROC curve, MTTD/MTTR comparison |
| **ATT&CK Heatmap** | Actor × tactic technique count heatmap |
| **Network Graph** | D3 force-directed IT/OT network topology |
| **Geo Risk** | D3 globe with nation-state threat actor overlays |
| **Kill Chain Builder** | Drag-and-compose custom ICS kill chains · Export as MITRE Navigator layer |
| **CVE Asset Map** | 25 ICS CVEs mapped to Purdue level, vendor, CVSS, KEV status |
| **Threat Intel Platforms** | ThreatFox · Feodo · URLhaus · MalwareBazaar · CISA · GreyNoise · Shodan — with live links |
| **Datasets** | Research dataset catalog (SWAT, BATADAL, GasP, etc.) |
| **References** | Academic citations and standards |

---

## Threat Intelligence Sources

| Source | Type | Auth Required |
|---|---|---|
| ThreatFox (Abuse.ch) | Malware C2 IOCs | No |
| Feodo Tracker (Abuse.ch) | Botnet C2 blocklist | No |
| URLhaus (Abuse.ch) | Malicious URLs | No |
| MalwareBazaar (Abuse.ch) | Malware samples | No |
| CISA KEV | Known exploited vulnerabilities | No |
| CISA ICS Advisories | ICS-CERT RSS feed | No |
| NIST NVD | CVE database | No |
| GreyNoise | ICS scanner intelligence | Optional (free tier available) |
| Shodan | Internet-exposed ICS devices | Optional |
| AlienVault OTX | Threat pulses | Optional |

---

## Threat Actor Coverage

Full intelligence profiles (campaigns, TTPs, IOCs, MITRE techniques, source attribution) for:

- **Russia:** Sandworm (APT44), TRITON/TEMP.Veles (XENOTIME), BlackEnergy/Quedagh
- **China:** Volt Typhoon, VOLTZITE, APT40
- **Iran:** APT33 (Peach Sandstorm), APT34 (OilRig), HEXANE (Lyceum), MuddyWater
- **North Korea:** Lazarus Group, Kimsuky
- **Belarus:** Ghostwriter (UNC1151)
- **Unknown:** CHERNOVITE (PIPEDREAM/INCONTROLLER developers)

---

## Research Context

Built as part of **GWU SEAS 8499 — Doctoral Practicum** research on ML-assisted security orchestration, automation, and response (ML-SOAR) for cyber-physical systems. The ML-SOAR module implements Z-score anomaly detection on the SWAT (Secure Water Treatment) dataset, demonstrating measurable reduction in Mean Time to Detect (MTTD) compared to signature-based baseline detection.

**Key Research Metrics (synthetic SWAT simulation):**
- Detection Accuracy: 93.1% (ML-SOAR) vs ~65% (signature baseline)
- MTTD Improvement: ~82% reduction
- False Positive Rate: 4.9%

---

*CyberShark Security™ — GWU SEAS 8499 Doctoral Practicum*
