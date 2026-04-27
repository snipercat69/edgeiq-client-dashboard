# EdgeIQ Client Dashboard

A lightweight, stdlib-only per-customer security portal. Customers log in to see their scan history, SSL expirations, risk scores, alert summaries, and generated reports — all without a database or pip dependencies.

---

## Features

- **At-a-glance risk scores** per client (0–100, with grade: Low / Medium / High / Critical)
- **Per-client views** — targets, SSL cert timeline, recent alerts, risk breakdown
- **Report access** — links to PDF/HTML reports per client
- **Alert history** — full log with severity, source, and timestamp
- **Risk score engine** — driven by critical findings, open ports, SSL issues, and alert frequency
- **JSON API** — POST endpoint accepts scan results from other EdgeIQ tools
- **Token auth** — simple Bearer token login; auto-generates credentials on first run
- **Cron-friendly** — persistent service mode or one-shot data ingestion mode
- **Zero pip dependencies** — Python standard library only

---

## Requirements

- Python 3.7+ (stdlib only)
- No external packages required

---

## Quick Start

```bash
cd apps/edgeiq-client-dashboard
python3 scripts/dashboard.py
```

On first run without `AUTH_TOKEN` set, a random token is generated and printed to the console:

```
[EdgeIQ] AUTH_TOKEN not set — generated token: <random-token>
[EdgeIQ] Save this token! It will not be shown again.
[EdgeIQ] Dashboard running at http://localhost:8080/
```

Navigate to `http://localhost:8080/login`, enter the token, and you're in.

To persist the token across restarts, set it in the environment:

```bash
AUTH_TOKEN=your-secret-token python3 scripts/dashboard.py
```

Or create a `.env` file (copy from `.env.example`):

```bash
cp .env.example .env
# Edit .env and set your AUTH_TOKEN
```

---

## Configuration

| Environment variable | Default | Description |
|---|---|---|
| `AUTH_TOKEN` | auto-generated | Bearer token for dashboard login |
| `DASHBOARD_PORT` | `8080` | HTTP port the dashboard listens on |
| `DASHBOARD_DATA_DIR` | `../` (parent of `scripts/`) | Directory containing `clients/` subfolder |

---

## Architecture

```
edgeiq-client-dashboard/
├── SKILL.md               # Skill metadata
├── README.md              # This file
├── .env.example           # Environment variable template
├── config.json.example    # Config file template
├── sample-client.json    # Full client record schema
├── scripts/
│   └── dashboard.py      # Main application
└── clients/              # JSON files created at runtime
    ├── acme-corp.json
    └── globex-inc.json
```

Each client is stored as a standalone JSON file: `clients/<client_id>.json`.

---

## Feeding Data from EdgeIQ Tools

Other EdgeIQ tools can push scan results to the dashboard via the REST API.

### Create a new client

```bash
curl -X POST http://localhost:8080/api/clients \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Corp",
    "client_id": "acme-corp",
    "contact_email": "security@acme.com",
    "targets": [{"host": "acme.com", "status": "up"}]
  }'
```

### Push scan results to an existing client

```bash
curl -X POST http://localhost:8080/api/clients/acme-corp/scan \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "acme.com",
    "scan_date": "2026-04-23",
    "open_ports": [
      {"port": 443, "service": "https", "state": "open"},
      {"port": 22,  "service": "ssh",   "state": "open"}
    ],
    "ssl_certs": [
      {
        "host": "acme.com",
        "fingerprint": "SHA1-FINGERPRINT",
        "issuer": "DigiCert",
        "expires": "2026-08-15"
      }
    ],
    "findings": [
      {
        "severity": "critical",
        "title": "Open SQL database port",
        "description": "Port 3306 is exposed to the internet."
      }
    ],
    "alerts": [
      {
        "severity": "high",
        "title": "Unpatched OpenSSH version",
        "source": "nmap",
        "timestamp": "2026-04-23T10:00:00Z"
      }
    ],
    "reports": [
      {
        "name": "Acme Corp — Full Security Scan",
        "type": "pdf",
        "url": "/reports/acme-corp-20260423.pdf"
      }
    ]
  }'
```

The dashboard automatically recalculates the risk score after each scan is ingested.

### One-shot mode

If your scanning tool outputs a JSON file, you can bulk-load it without running the server:

```bash
python3 scripts/dashboard.py --oneshot scan-results.json
```

The JSON should be either a single client object or a list of client objects. See `sample-client.json` for the full schema.

---

## API Reference

### `POST /api/clients`
Create a new client.

### `GET /api/clients`
List all clients with their risk scores.

### `GET /api/clients/<client_id>`
Get full details for one client.

### `POST /api/clients/<client_id>/scan`
Ingest scan results into a client record. Merges targets, ports, SSL certs, findings, alerts, and reports.

### `POST /api/clients/<client_id>`
Upsert a full client record (replace fields provided).

### `GET /api/alerts`
Returns a JSON summary of all alerts across all clients, bucketed by severity.

### `GET /api/health`
Health check. Returns `{"status": "ok", "version": "1.0.0"}`.

All endpoints require `Authorization: Bearer <TOKEN>` header except `/login` and `/api/health`.

---

## Risk Score Algorithm

| Factor | Weight per unit | Max contribution |
|---|---|---|
| Critical finding | 40 pts each | 40 |
| High finding | 25 pts each | — |
| Medium finding | 10 pts each | — |
| Open ports | 2 pts each (max 30) | 30 |
| Expired SSL cert | 10 pts each | 40 |
| SSL cert expiring < 7 days | 10 pts each | 40 |
| SSL cert expiring < 30 days | 10 pts each | 40 |
| Alert (last 30 days) | 3 pts each (max 30) | 30 |

Final score is capped at 100 and mapped to a grade:
- **0–20** → Low (green)
- **21–50** → Medium (yellow)
- **51–75** → High (orange)
- **76–100** → Critical (red)

---

## Demo Clients

Two sample clients are included so the dashboard shows content immediately on first run:
- `clients/acme-corp.json`
- `clients/globex-inc.json`

Delete them to start fresh, or edit them to match your environment.

---

## Legal Notice

**For authorized security monitoring only.** You are solely responsible for ensuring you have explicit permission to scan and monitor any targets accessible through this portal. Unauthorized scanning may violate applicable laws including the Computer Fraud and Abuse Act (CFAA) and similar state or international legislation. EdgeIQ Labs and its authors accept no liability for misuse of this tool.
