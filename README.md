# 📊 EdgeIQ Client Dashboard

**Agency client management dashboard for tracking security assessments, scan results, and billing.**

Manage multiple client accounts, track security scan history, view vulnerability reports, and monitor subscription status in one unified interface.

[![Project Stage](https://img.shields.io/badge/Stage-Beta-blue)](https://edgeiqlabs.com)
[![Python](https://img.shields.io/badge/Python-3.8+-green)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-orange)](LICENSE)

---

## What It Does

A unified dashboard for agencies managing multiple security assessment clients. Track scan results, view vulnerability history, manage subscriptions, and export client reports.

---

## Key Features

- **Multi-client management** — organize clients by name, industry, and risk tier
- **Scan history tracking** — record and compare security scan results over time
- **Vulnerability dashboards** — visual summary of findings by severity and category
- **Subscription management** — track Pro/Free tier and billing status
- **JSON export** — structured client data for integration with external tools
- **Flask-based** — runs on any Python environment, no heavy dependencies

---

## Prerequisites

- Python 3.8 or higher
- `flask` and `requests` libraries

---

## Installation

```bash
git clone https://github.com/snipercat69/edgeiq-client-dashboard.git
cd edgeiq-client-dashboard
pip install -r requirements.txt
cp config.json.example config.json
# Edit config.json
python3 scripts/run_dashboard.py
```

---

## Quick Start

```bash
# Run dashboard (default port 5000)
python3 scripts/run_dashboard.py

# Run on custom port
python3 scripts/run_dashboard.py --port 8080

# Export client data
python3 scripts/export_clients.py --format json
```

---

## Pricing

| Tier | Price | Features |
|------|-------|----------|
| **Free** | $0 | 3 clients, basic tracking |
| **Pro** | $15/mo | Unlimited clients, export features, priority support |
| **Lifetime** | $80 one-time | All Pro features, forever |

---

## Support

Open an issue at: https://github.com/snipercat69/edgeiq-client-dashboard/issues

---

*Part of EdgeIQ Labs — [edgeiqlabs.com](https://edgeiqlabs.com)*
