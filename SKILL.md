# EdgeIQ Client Dashboard — Skill Metadata

skill:
  name: edgeiq-client-dashboard
  version: 1.0.0
  category: Security Intelligence / Client Portal
  description: >
    A lightweight, stdlib-only client portal for managed security services.
    Gives customers their own login to see scan history, SSL expirations,
    risk scores, alert summaries, and self-serve report access — tied
    together from the EdgeIQ tool suite. Designed to be self-hosted,
    cron-friendly, and feedable via POST from other EdgeIQ scanners.
  tier: Pro
  price: $29/mo

  tiers:
    Free:
      - 1 client
      - 3 targets max
      - Basic risk score (findings count only)
      - Text summary view only
    Pro:
      - Unlimited clients and targets
      - Full risk scoring algorithm (findings × severity + ports + SSL + alerts)
      - PDF and HTML report access
      - Email digest (weekly/monthly)
      - Slack and Telegram integration
      - API rate limits: 100 req/min
    Bundle:
      - Included with all EdgeIQ skill bundles

  features:
    - Per-customer login with token-based auth
    - Client overview grid with risk badges
    - Per-client tabs: Summary, Targets, SSL Timeline, Alerts, Reports, Risk Breakdown
    - Interactive SVG risk gauge per client
    - SSL certificate expiry timeline with color-coded warnings
    - Scan history tracking (last scan date, port findings)
    - Alert history with severity filtering
    - Self-serve report links (PDF, HTML, Summary)
    - JSON-based client records — no database needed
    - One-shot mode for cron ingestion of scan data
    - POST API to register clients and apply scan results
    - Alert summary endpoint (cross-client aggregation)
    - Dark theme UI matching EdgeIQ brand
    - Token auto-generation on first run
    - Configurable via env vars (AUTH_TOKEN, DASHBOARD_PORT, DASHBOARD_DATA_DIR)

  usage:
    - Run continuously: `python3 scripts/dashboard.py`
    - Run one-shot for a scan file: `python3 scripts/dashboard.py --oneshot scan.json`
    - POST client registration: `POST /api/clients` with JSON body
    - POST scan result: `POST /api/clients/<id>/scan` with scan JSON
    - GET clients: `GET /api/clients` (Bearer token auth)
    - GET alerts summary: `GET /api/alerts` (Bearer token auth)
    - Health check: `GET /api/health` (no auth)

  examples:
    # Start dashboard on port 9000 with custom token
    AUTH_TOKEN=mysecret DASHBOARD_PORT=9000 python3 scripts/dashboard.py

    # Feed a scan result file (one-shot mode)
    python3 scripts/dashboard.py --oneshot /path/to/scan-result.json

    # Register a new client via API
    curl -X POST http://localhost:8080/api/clients \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d '{"name":"BigCo","contact_email":"security@bigco.com"}'

    # Apply a scan result to an existing client
    curl -X POST http://localhost:8080/api/clients/acme-corp/scan \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d @scan-output.json

  legal: |
    This skill is provided as-is for legitimate managed security service
    deployments. It is designed exclusively for authorized security scanning
    and client-facing portal use. Unauthorized access to systems or networks
    is prohibited. SSL certificate data is fetched passively only from
    configurations you have explicit permission to test.


---

## 🔗 More from EdgeIQ Labs

**edgeiqlabs.com** — Security tools, OSINT utilities, and micro-SaaS products for developers and security professionals.

- 🛠️ **Subdomain Hunter** — Passive subdomain enumeration via Certificate Transparency
- 📸 **Screenshot API** — URL-to-screenshot API for developers
- 🔔 **uptime.check** — URL uptime monitoring with alerts
- 🛡️ **headers.check** — HTTP security headers analyzer

👉 [Visit edgeiqlabs.com →](https://edgeiqlabs.com)
