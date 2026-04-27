#!/usr/bin/env python3
"""
EdgeIQ Client Dashboard  v1.0.0
A lightweight stdlib-only client portal for managed security services.
Serves scan history, SSL expirations, risk scores, alerts, and report links.
No pip dependencies — built entirely on Python standard library.
"""

import json
import os
import sys
import secrets
import hashlib
import re
import datetime
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PORT = int(os.getenv("DASHBOARD_PORT", "8080"))
AUTH_TOKEN = os.getenv("AUTH_TOKEN", "")
DATA_DIR = os.getenv("DASHBOARD_DATA_DIR",
                    os.path.join(os.path.dirname(__file__), ".."))
CLIENTS_DIR = os.path.join(DATA_DIR, "clients")

# ---------------------------------------------------------------------------
# Token management
# ---------------------------------------------------------------------------
def get_token():
    global AUTH_TOKEN
    if not AUTH_TOKEN:
        AUTH_TOKEN = os.getenv("AUTH_TOKEN", "") or secrets.token_urlsafe(32)
    return AUTH_TOKEN


def require_auth(handler):
    auth = handler.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        handler.send_error(401, "Authorization header required")
        return False
    if not secrets.compare_digest(auth[7:], get_token()):
        handler.send_error(401, "Invalid token")
        return False
    return True


def send_json(handler, status, data):
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(json.dumps(data, default=str).encode())


# ---------------------------------------------------------------------------
# Client storage
# ---------------------------------------------------------------------------
def clients_dir():
    os.makedirs(CLIENTS_DIR, exist_ok=True)
    return CLIENTS_DIR


def client_path(cid):
    return os.path.join(clients_dir(), cid + ".json")


def load_client(cid):
    p = client_path(cid)
    if not os.path.exists(p):
        return None
    with open(p) as f:
        return json.load(f)


def save_client(cid, data):
    with open(client_path(cid), "w") as f:
        json.dump(data, f, indent=2, default=str)


def list_clients():
    os.makedirs(clients_dir(), exist_ok=True)
    out = []
    for fname in os.listdir(clients_dir()):
        if fname.endswith(".json"):
            c = load_client(fname[:-5])
            if c:
                out.append(c)
    return sorted(out, key=lambda x: x.get("name", ""))


def next_client_id():
    return uuid.uuid4().hex[:12]


# ---------------------------------------------------------------------------
# Risk score engine
# ---------------------------------------------------------------------------
def compute_risk_score(client):
    score = 0
    details = {}

    findings = client.get("findings", [])
    crit = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    med  = sum(1 for f in findings if f.get("severity") == "medium")
    score += crit * 40 + high * 25 + med * 10
    details["findings"] = {
        "critical": crit, "high": high, "medium": med,
        "score_contribution": crit * 40 + high * 25 + med * 10,
    }

    ports = client.get("open_ports", [])
    pc = len(ports)
    ps = min(pc * 2, 30)
    score += ps
    details["open_ports"] = {"count": pc, "score_contribution": ps}

    today = datetime.date.today()
    si = 0
    for cert in client.get("ssl_certs", []):
        try:
            diff = (datetime.date.fromisoformat(cert["expires"]) - today).days
            if diff < 0:
                si += 3
            elif diff < 7:
                si += 2
            elif diff < 30:
                si += 1
        except (ValueError, TypeError):
            si += 1
    score += min(si * 10, 40)
    details["ssl_issues"] = {"count": si, "score_contribution": min(si * 10, 40)}

    cutoff = (today - datetime.timedelta(days=30)).isoformat()
    recent = [a for a in client.get("alerts", []) if a.get("timestamp", "") >= cutoff]
    ac = len(recent)
    score += min(ac * 3, 30)
    details["recent_alerts"] = {"count": ac, "score_contribution": min(ac * 3, 30)}

    raw = max(0, min(score, 100))
    if raw <= 20:
        grade = "low"
    elif raw <= 50:
        grade = "medium"
    elif raw <= 75:
        grade = "high"
    else:
        grade = "critical"
    return {"score": raw, "grade": grade, "details": details}


def update_client_risk(cid):
    c = load_client(cid)
    if not c:
        return None
    risk = compute_risk_score(c)
    c["risk_score"] = risk["score"]
    c["risk_grade"] = risk["grade"]
    c["risk_breakdown"] = risk["details"]
    c["last_activity"] = datetime.datetime.utcnow().isoformat() + "Z"
    save_client(cid, c)
    return c


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------
def hesc(s):
    if s is None:
        return ""
    s = str(s)
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


def risk_badge(grade, score):
    dot = ("dot-online" if grade == "low"
           else "dot-warning" if grade == "medium"
           else "dot-danger")
    return ('<span class="risk-badge risk-' + grade + '">'
            '<span class="status-dot ' + dot + '"></span>'
            + str(score) + ' / 100 \u2014 ' + grade.upper() + '</span>')


# ---------------------------------------------------------------------------
# Dark CSS
# ---------------------------------------------------------------------------
CSS = (
    ":root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--accent:#58a6ff;"
    "--accent-dim:#1f4068;--green:#3fb950;--yellow:#d29922;--red:#f85149;"
    "--orange:#e8963a;--text:#c9d1d9;--muted:#8b949e}"
    "*{box-sizing:border-box;margin:0;padding:0}"
    "body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:14px;line-height:1.5}"
    "a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}"
    "header{background:var(--surface);border-bottom:1px solid var(--border);padding:0 24px;display:flex;align-items:center;gap:12px;height:56px}"
    "header .logo{font-size:18px;font-weight:700;color:var(--accent)}"
    "header .logo span{color:var(--text)}"
    "header nav{margin-left:auto;display:flex;gap:4px}"
    "header nav a{color:var(--muted);padding:6px 12px;border-radius:6px;font-size:13px}"
    "header nav a:hover,header nav a.active{background:var(--accent-dim);color:var(--accent);text-decoration:none}"
    "header .logout-btn{color:var(--muted);padding:6px 12px;border-radius:6px;font-size:13px;cursor:pointer;background:none;border:none;font-family:inherit}"
    "header .logout-btn:hover{background:var(--accent-dim);color:var(--red)}"
    ".container{max-width:1200px;margin:0 auto;padding:24px}"
    ".section-title{font-size:16px;font-weight:600;color:var(--text);margin-bottom:16px;display:flex;align-items:center;gap:8px}"
    ".section-title .badge{background:var(--accent-dim);color:var(--accent);font-size:11px;padding:2px 7px;border-radius:20px;font-weight:500}"
    ".card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:16px}"
    ".client-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px}"
    ".client-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;cursor:pointer;transition:border-color 0.15s}"
    ".client-card:hover{border-color:var(--accent);text-decoration:none}"
    ".client-card .client-name{font-size:15px;font-weight:600;color:var(--text);margin-bottom:6px}"
    ".client-card .client-email{font-size:12px;color:var(--muted);margin-bottom:12px}"
    ".client-card .client-meta{display:flex;justify-content:space-between;align-items:center}"
    ".risk-badge{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:20px;font-size:12px;font-weight:600}"
    ".risk-low{background:rgba(63,185,80,0.15);color:var(--green);border:1px solid rgba(63,185,80,0.3)}"
    ".risk-medium{background:rgba(210,153,34,0.15);color:var(--yellow);border:1px solid rgba(210,153,34,0.3)}"
    ".risk-high{background:rgba(232,150,58,0.15);color:var(--orange);border:1px solid rgba(232,150,58,0.3)}"
    ".risk-critical{background:rgba(248,81,73,0.15);color:var(--red);border:1px solid rgba(248,81,73,0.3)}"
    ".detail-row{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border);font-size:13px}"
    ".detail-row:last-child{border-bottom:none}.detail-row .label{color:var(--muted)}.detail-row .value{font-weight:500}"
    ".target-list{list-style:none;margin-top:8px}"
    ".target-list li{padding:6px 0;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;font-size:13px}"
    ".target-list li:last-child{border-bottom:none}.target-list .target-host{font-family:'Courier New',monospace;color:var(--accent)}"
    ".ssl-timeline{margin-top:12px}"
    ".ssl-item{display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border);font-size:12px}"
    ".ssl-item:last-child{border-bottom:none}.ssl-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}"
    ".ssl-ok{background:var(--green)}.ssl-warn{background:var(--yellow)}.ssl-crit{background:var(--red)}.ssl-expired{background:var(--red);opacity:0.5}"
    ".ssl-info{color:var(--muted);font-size:11px}"
    ".alert-item{padding:10px 0;border-bottom:1px solid var(--border)}.alert-item:last-child{border-bottom:none}"
    ".alert-header{display:flex;align-items:center;gap:8px;margin-bottom:4px}"
    ".alert-severity{font-size:11px;font-weight:700;padding:2px 8px;border-radius:4px;text-transform:uppercase}"
    ".sev-critical{background:rgba(248,81,73,0.2);color:var(--red)}.sev-high{background:rgba(232,150,58,0.2);color:var(--orange)}"
    ".sev-medium{background:rgba(210,153,34,0.2);color:var(--yellow)}.sev-low{background:rgba(63,185,80,0.15);color:var(--green)}"
    ".sev-info{background:var(--accent-dim);color:var(--accent)}.alert-title{font-size:13px;font-weight:500}.alert-meta{font-size:11px;color:var(--muted)}"
    ".alert-source{color:var(--muted);font-family:'Courier New',monospace;font-size:11px}"
    ".breakdown-bar{display:flex;height:8px;border-radius:4px;overflow:hidden;background:var(--border);margin:8px 0}"
    ".breakdown-seg{height:100%}"
    ".breakdown-legend{display:flex;gap:16px;flex-wrap:wrap}"
    ".breakdown-legend span{font-size:11px;color:var(--muted);display:flex;align-items:center;gap:4px}.breakdown-legend .dot{width:8px;height:8px;border-radius:50%}"
    ".report-link{display:flex;align-items:center;gap:8px;padding:10px 0;border-bottom:1px solid var(--border)}.report-link:last-child{border-bottom:none}.report-link a{flex:1}"
    ".report-type{font-size:11px;padding:2px 7px;border-radius:4px;font-weight:600}"
    ".type-pdf{background:rgba(248,81,73,0.15);color:var(--red)}.type-html{background:rgba(88,166,255,0.15);color:var(--accent)}.type-summary{background:rgba(63,185,80,0.15);color:var(--green)}"
    ".back-link{display:inline-flex;align-items:center;gap:6px;color:var(--muted);font-size:13px;margin-bottom:16px}.back-link:hover{color:var(--accent);text-decoration:none}"
    ".login-wrapper{min-height:100vh;display:flex;align-items:center;justify-content:center}"
    ".login-box{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:40px;width:360px}"
    ".login-box h1{font-size:22px;font-weight:700;margin-bottom:4px;color:var(--text)}"
    ".login-box .subtitle{color:var(--muted);font-size:13px;margin-bottom:28px}"
    ".form-group{margin-bottom:16px}.form-group label{display:block;font-size:12px;color:var(--muted);margin-bottom:6px;font-weight:500}"
    ".form-group input{width:100%;padding:9px 12px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:14px;font-family:inherit;outline:none;transition:border-color 0.15s}"
    ".form-group input:focus{border-color:var(--accent)}"
    ".btn-primary{width:100%;padding:10px;background:var(--accent);color:#fff;border:none;border-radius:6px;font-size:14px;font-weight:600;cursor:pointer;font-family:inherit}.btn-primary:hover{opacity:0.9}"
    ".login-error{color:var(--red);font-size:13px;margin-bottom:12px;display:none}.login-error.show{display:block}"
    ".demo-hint{margin-top:20px;padding-top:16px;border-top:1px solid var(--border);font-size:11px;color:var(--muted)}"
    ".empty-state{text-align:center;padding:60px 20px;color:var(--muted)}.empty-state .icon{font-size:40px;margin-bottom:12px;opacity:0.4}.empty-state h3{font-size:16px;color:var(--text);margin-bottom:6px}.empty-state p{font-size:13px}"
    ".status-dot{width:8px;height:8px;border-radius:50%;display:inline-block}.dot-online{background:var(--green)}.dot-warning{background:var(--yellow)}.dot-danger{background:var(--red)}"
    ".grid-2{display:grid;grid-template-columns:1fr 1fr;gap:16px}"
    "@media(max-width:768px){.grid-2{grid-template-columns:1fr}}"
    ".tab-bar{display:flex;gap:4px;margin-bottom:20px;border-bottom:1px solid var(--border);padding-bottom:0}"
    ".tab-btn{padding:8px 16px;border-radius:6px 6px 0 0;font-size:13px;color:var(--muted);cursor:pointer;border:none;background:none;font-family:inherit;transition:color 0.15s}"
    ".tab-btn:hover{color:var(--text)}.tab-btn.active{color:var(--accent);border-bottom:2px solid var(--accent)}"
    ".tab-panel{display:none}.tab-panel.active{display:block}"
    ".spinner{border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;width:24px;height:24px;animation:spin 0.7s linear infinite;margin:40px auto}"
    "@keyframes spin{to{transform:rotate(360deg)}}"
    ".gauge-wrap{display:flex;flex-direction:column;align-items:center;margin:16px 0}"
    ".gauge-svg{transform:rotate(-90deg)}.gauge-bg{fill:none;stroke:var(--border);stroke-width:8}"
    ".gauge-fill{fill:none;stroke-width:8;stroke-linecap:round;transition:stroke-dashoffset 0.5s}"
    "footer{text-align:center;padding:24px;color:var(--muted);font-size:11px;border-top:1px solid var(--border);margin-top:40px}footer a{color:var(--muted)}"
)

LOGIN_HTML = (
    "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1.0'>"
    "<title>EdgeIQ Client Portal</title>"
    "<style>" + CSS + "</style></head><body>"
    "<div class='login-wrapper'>"
    "<div class='login-box'>"
    "<h1>EdgeIQ <span style='color:var(--accent)'>Client Portal</span></h1>"
    "<p class='subtitle'>Sign in to view your security dashboard</p>"
    "<div class='login-error' id='err'>Invalid token. Please try again.</div>"
    "<form id='login-form'>"
    "<div class='form-group'><label for='token'>Access Token</label>"
    "<input type='password' id='token' placeholder='Enter your access token' autocomplete='current-password'></div>"
    "<button type='submit' class='btn-primary'>Sign In</button>"
    "</form>"
    "<div class='demo-hint'><strong>Demo mode:</strong> Set <code>AUTH_TOKEN</code> env var to your token."
    " On first run without it, a token is auto-generated and printed to the console.</div>"
    "</div></div>"
    "<script>"
    "document.getElementById('login-form').addEventListener('submit',function(e){"
    "e.preventDefault();var tok=document.getElementById('token').value;"
    "fetch('/api/me',{method:'POST',headers:{'Authorization':'Bearer '+tok}})"
    ".then(function(r){if(r.ok){sessionStorage.setItem('eq_tok',tok);window.location.href='/';}"
    "else{document.getElementById('err').classList.add('show');}"
    "}).catch(function(){document.getElementById('err').classList.add('show');});"
    "});</script></body></html>"
)


def targets_html(targets):
    if not targets:
        return "<p style='color:var(--muted);font-size:13px'>No targets registered.</p>"
    items = []
    for t in targets:
        host = hesc(t.get("host") or t.get("url") or str(t))
        dot = "dot-online" if t.get("status") == "up" else "dot-danger"
        items.append("<li><span class='target-host'>" + host + "</span>"
                    "<span class='status-dot " + dot + "'></span></li>")
    return "<ul class='target-list'>" + "".join(items) + "</ul>"


def ssl_item_html(cert):
    today = datetime.date.today().isoformat()
    exp = cert.get("expires") or ""
    host = hesc(cert.get("host") or cert.get("target") or "?")
    if exp:
        try:
            diff = (datetime.date.fromisoformat(exp) - datetime.date.today()).days
            if diff < 0:
                dot, txt = "ssl-expired", "EXPIRED"
            elif diff < 7:
                dot, txt = "ssl-crit", str(round(diff)) + " days left"
            elif diff < 30:
                dot, txt = "ssl-warn", str(round(diff)) + " days left"
            else:
                dot, txt = "ssl-ok", str(round(diff)) + " days left"
        except (ValueError, TypeError):
            dot, txt = "ssl-warn", "?"
    else:
        dot, txt = "ssl-warn", "\u2014"
    exp_txt = "Expires " + exp if exp else "No expiry data"
    return ("<div class='ssl-item'><span class='ssl-dot " + dot + "'></span>"
            "<span class='target-host'>" + host + "</span>"
            "<span class='ssl-info'>" + txt + "</span>"
            "<span class='ssl-info'>" + exp_txt + "</span></div>")


def alert_item_html(a):
    sev = (a.get("severity") or "info").lower()
    title = hesc(a.get("title") or a.get("message") or "\u2014")
    src = (("<span class='alert-source'>" + hesc(a.get("source") or "") + "</span>")
           if a.get("source") else "")
    ts = (" \u2014 " + hesc(a.get("timestamp") or "")
          if a.get("timestamp") else "")
    return ("<div class='alert-item'><div class='alert-header'>"
            "<span class='alert-severity sev-" + sev + "'>" + sev + "</span>"
            "<span class='alert-title'>" + title + "</span></div>"
            "<div class='alert-meta'>" + src + ts + "</div></div>")


def report_link_html(r):
    rtype = (r.get("type") or "summary").lower()
    cls = ("type-pdf" if "pdf" in rtype
           else "type-html" if "html" in rtype
           else "type-summary")
    name = hesc(r.get("name") or r.get("title") or "Report")
    url = r.get("url") or "#"
    has_url = bool(r.get("url"))
    style = "" if has_url else "style='pointer-events:none;opacity:0.4'"
    date = hesc(r.get("date") or "")
    return ("<div class='report-link'>"
            "<span class='report-type " + cls + "'>" + rtype.upper() + "</span>"
            "<a href='" + hesc(url) + "' " + style + ">" + name + "</a>"
            "<span style='font-size:11px;color:var(--muted)'>" + date + "</span></div>")


def client_tab_html(c):
    grade = c.get("risk_grade") or "low"
    score = c.get("risk_score") or 0
    color = {"low": "var(--green)", "medium": "var(--yellow)",
             "high": "var(--orange)", "critical": "var(--red)"}.get(grade, "var(--muted)")
    cname = hesc(c.get("name") or "")
    cmail = hesc(c.get("contact_email") or "")
    badge = risk_badge(grade, score)
    last_scan = hesc(c.get("last_scan_date") or "Never")
    n_targets = len(c.get("targets") or [])
    n_ports = len(c.get("open_ports") or [])
    findings = c.get("findings") or []
    n_crit = sum(1 for f in findings if f.get("severity") == "critical")
    n_ssl = len(c.get("ssl_certs") or [])
    n_alerts = len(c.get("alerts") or [])
    circ = 2 * 3.14159265358979 * 50
    offset = ((1 - score / 100) * circ)
    gauge = (
        "<div class='gauge-wrap'>"
        "<svg class='gauge-svg' width='120' height='120' viewBox='0 0 120 120'>"
        "<circle class='gauge-bg' cx='60' cy='60' r='50'/>"
        "<circle class='gauge-fill' cx='60' cy='60' r='50' stroke='" + color + "' "
        "stroke-dasharray='" + str(circ) + "' stroke-dashoffset='" + str(offset) + "'/>"
        "</svg>"
        "<span style='font-size:28px;font-weight:700;color:" + color + ";margin-top:-70px;position:relative;top:-10px'>" + str(score) + "</span>"
        "<span style='font-size:12px;color:var(--muted)'>out of 100 \u2014 " + grade.upper() + "</span>"
        "</div>"
    )
    targets_h = targets_html(c.get("targets"))
    ssl_h = "".join(ssl_item_html(x) for x in (c.get("ssl_certs") or []))
    if not ssl_h:
        ssl_h = "<p style='color:var(--muted);font-size:13px'>No SSL certificate data.</p>"
    alerts_h = "".join(alert_item_html(a) for a in (c.get("alerts") or [])[:20])
    if not alerts_h:
        alerts_h = "<p style='color:var(--muted);font-size:13px'>No recent alerts.</p>"
    reports_h = "".join(report_link_html(r) for r in (c.get("reports") or []))
    if not reports_h:
        reports_h = "<p style='color:var(--muted);font-size:13px'>No reports available. Run a scan to generate reports.</p>"
    br = c.get("risk_breakdown") or {}
    fin = br.get("findings") or {}
    br_f = int((fin.get("score_contribution") or 0))
    br_p = int((br.get("open_ports") or {}).get("score_contribution") or 0)
    br_s = int((br.get("ssl_issues") or {}).get("score_contribution") or 0)
    br_a = int((br.get("recent_alerts") or {}).get("score_contribution") or 0)
    bar = (
        "<div class='breakdown-bar'>"
        "<div class='breakdown-seg' style='flex:" + str(br_f) + ";background:var(--red)'></div>"
        "<div class='breakdown-seg' style='flex:" + str(br_p) + ";background:var(--orange)'></div>"
        "<div class='breakdown-seg' style='flex:" + str(br_s) + ";background:var(--yellow)'></div>"
        "<div class='breakdown-seg' style='flex:" + str(br_a) + ";background:var(--accent)'></div>"
        "</div>"
    )
    legend = (
        "<div class='breakdown-legend'>"
        "<span><span class='dot' style='background:var(--red)'></span>Findings (" + str(br_f) + "%)</span>"
        "<span><span class='dot' style='background:var(--orange)'></span>Ports (" + str(br_p) + "%)</span>"
        "<span><span class='dot' style='background:var(--yellow)'></span>SSL (" + str(br_s) + "%)</span>"
        "<span><span class='dot' style='background:var(--accent)'></span>Alerts (" + str(br_a) + "%)</span>"
        "</div>"
    )
    details = (
        "<div style='margin-top:16px'>"
        "<div class='detail-row'><span class='label'>Critical findings</span>"
        "<span class='value'>" + str(fin.get("critical") or 0) + " critical, " + str(fin.get("high") or 0) + " high, " + str(fin.get("medium") or 0) + " medium</span></div>"
        "<div class='detail-row'><span class='label'>Open ports</span>"
        "<span class='value'>" + str((br.get("open_ports") or {}).get("count") or 0) + " open ports</span></div>"
        "<div class='detail-row'><span class='label'>SSL issues</span>"
        "<span class='value'>" + str((br.get("ssl_issues") or {}).get("count") or 0) + " issues detected</span></div>"
        "<div class='detail-row'><span class='label'>Recent alerts (30d)</span>"
        "<span class='value'>" + str((br.get("recent_alerts") or {}).get("count") or 0) + " alerts</span></div>"
        "</div>"
    )
    return (
        "<a href='/' class='back-link'>&#8592; Back to Overview</a>"
        "<div style='display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:20px'>"
        "<div><h2 style='font-size:20px;font-weight:700;margin-bottom:4px'>" + cname + "</h2>"
        "<p style='color:var(--muted);font-size:13px'>" + cmail + "</p></div>"
        + badge +
        "</div>"
        "<div class='tab-bar'>"
        "<button class='tab-btn active' id='tab-btn-summary' onclick=\"showTab('summary')\">Summary</button>"
        "<button class='tab-btn' id='tab-btn-targets' onclick=\"showTab('targets')\">Targets</button>"
        "<button class='tab-btn' id='tab-btn-ssl' onclick=\"showTab('ssl')\">SSL</button>"
        "<button class='tab-btn' id='tab-btn-alerts' onclick=\"showTab('alerts')\">Alerts</button>"
        "<button class='tab-btn' id='tab-btn-reports' onclick=\"showTab('reports')\">Reports</button>"
        "<button class='tab-btn' id='tab-btn-risk' onclick=\"showTab('risk')\">Risk Breakdown</button>"
        "</div>"
        "<div id='tab-summary' class='tab-panel active'>"
        "<div class='grid-2'>"
        "<div class='card'><div class='section-title'>Last Scan</div>"
        "<div class='detail-row'><span class='label'>Date</span><span class='value'>" + last_scan + "</span></div>"
        "<div class='detail-row'><span class='label'>Targets scanned</span><span class='value'>" + str(n_targets) + "</span></div>"
        "<div class='detail-row'><span class='label'>Open ports</span><span class='value'>" + str(n_ports) + "</span></div>"
        "<div class='detail-row'><span class='label'>Critical findings</span><span class='value' style='color:" + ("var(--red)" if n_crit else "inherit") + "'>" + str(n_crit) + "</span></div>"
        "<div class='detail-row'><span class='label'>SSL certs tracked</span><span class='value'>" + str(n_ssl) + "</span></div>"
        "</div>"
        "<div class='card' style='display:flex;flex-direction:column;align-items:center;justify-content:center'>"
        "<div class='section-title' style='align-self:flex-start'>Overall Risk Score</div>"
        + gauge +
        "</div></div></div>"
        "<div id='tab-targets' class='tab-panel'><div class='card'>"
        "<div class='section-title'>Monitored Targets <span class='badge'>" + str(n_targets) + "</span></div>"
        + targets_h + "</div></div>"
        "<div id='tab-ssl' class='tab-panel'><div class='card'>"
        "<div class='section-title'>SSL Certificate Timeline</div>"
        + ssl_h + "</div></div>"
        "<div id='tab-alerts' class='tab-panel'><div class='card'>"
        "<div class='section-title'>Recent Alerts <span class='badge'>" + str(n_alerts) + "</span></div>"
        + alerts_h + "</div></div>"
        "<div id='tab-reports' class='tab-panel'><div class='card'>"
        "<div class='section-title'>Available Reports</div>"
        + reports_h + "</div></div>"
        "<div id='tab-risk' class='tab-panel'><div class='card'>"
        "<div class='section-title'>Risk Score Breakdown</div>"
        + bar + legend + "<div class='breakdown-section'>" + details + "</div></div></div>"
    )


def overview_html(clients):
    if not clients:
        return ("<div class='empty-state'><div class='icon'>&#128269;</div>"
                "<h3>No Clients Yet</h3>"
                "<p>Feed scan data via the POST API to register your first client.</p></div>")
    cards = []
    for c in clients:
        grade = c.get("risk_grade") or "low"
        score = c.get("risk_score") or 0
        cid = hesc(c.get("client_id") or "")
        name = hesc(c.get("name") or "")
        email = hesc(c.get("contact_email") or "No contact")
        badge = risk_badge(grade, score)
        n = len(c.get("targets") or [])
        cards.append(
            "<a class='client-card' href='/?client=" + cid + "'>"
            "<div class='client-name'>" + name + "</div>"
            "<div class='client-email'>" + email + "</div>"
            "<div class='client-meta'>" + badge +
            "<span style='font-size:11px;color:var(--muted)'>" + str(n) + " targets</span></div>"
            "</a>"
        )
    heading = "<div class='section-title'>All Clients <span class='badge'>" + str(len(clients)) + "</span></div>"
    return heading + "<div class='client-grid'>" + "".join(cards) + "</div>"


def build_js(clients_json):
    return (
        "<script>"
        "var CLIENTS=" + clients_json + ";"
        "function gradeColor(g){return{low:'var(--green)',medium:'var(--yellow)',high:'var(--orange)',critical:'var(--red)'}[g]||'var(--muted)';}"
        "function esc(s){if(!s)return'';return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;');}"
        "function renderPage(){"
        "var u=new URLSearchParams(window.location.search);"
        "var id=u.get('client');"
        "var m=document.getElementById('main-content');"
        "if(id){var c;for(var i=0;i<CLIENTS.length;i++)if(CLIENTS[i].client_id===id){c=CLIENTS[i];break;}"
        "m.innerHTML=c?clientTab(c):\"<div class='empty-state'><h3>Client not found</h3><p><a href='/'>Back</a></p></div>\";}"
        "else{m.innerHTML=overviewTab();}"
        "}"
        "function overviewTab(){"
        "if(!CLIENTS.length)return\"<div class='empty-state'><div class='icon'>&#128269;</div><h3>No Clients Yet</h3><p>Feed scan data via POST API.</p></div>\";"
        "var h=\"<div class='section-title'>All Clients <span class='badge'>\"+CLIENTS.length+\"</span></div><div class='client-grid'>\";"
        "for(var i=0;i<CLIENTS.length;i++){var c=CLIENTS[i];var g=c.risk_grade||'low',s=c.risk_score||0;"
        "h+=\"<a class='client-card' href='/?client=\"+esc(c.client_id)+\"'>"
        "<div class='client-name'>\"+esc(c.name)+\"</div>"
        "<div class='client-email'>\"+esc(c.contact_email||'No contact')+\"</div>"
        "<div class='client-meta'><span class='risk-badge risk-\"+g+\"'>\"+s+\" / 100 \\u2014 \"+g.toUpperCase()+\"</span>"
        "<span style='font-size:11px;color:var(--muted)'>\"+(c.targets?c.targets.length:0)+\" targets</span></div></a>\";}"
        "return h+\"</div>\";"
        "}"
        "function sslItemHtml(c){"
        "var t=new Date().toISOString().slice(0,10),e=c.expires||'';var d='ssl-ok',txt='\\u2014';"
        "if(e){var n=(new Date(e)-new Date(t))/86400000;"
        "txt=Math.round(n)+\" days left\";d=n<0?'ssl-expired':n<7?'ssl-crit':n<30?'ssl-warn':'ssl-ok';}"
        "return\"<div class='ssl-item'><span class='ssl-dot \"+d+\"'></span><span class='target-host'>\"+esc(c.host||c.target||'?')+\"</span><span class='ssl-info'>\"+txt+\"</span><span class='ssl-info'>\"+(e?\"Expires \"+e:\"No expiry data\")+\"</span></div>\";"
        "}"
        "function alertItemHtml(a){var s=(a.severity||'info').toLowerCase();"
        "return\"<div class='alert-item'><div class='alert-header'>"
        "<span class='alert-severity sev-\"+s+\"'>\"+s+\"</span>"
        "<span class='alert-title'>\"+esc(a.title||a.message||'\\u2014')+\"</span></div>"
        "<div class='alert-meta'>\"+(a.source?\"<span class='alert-source'>\"+esc(a.source)+\"</span>\":'')"
        "+(a.timestamp?\" \\u2014 \"+esc(a.timestamp):'')+\"</div></div>\";"
        "}"
        "function clientTab(c){if(!c)return'';var g=c.risk_grade||'low',s=c.risk_score||0;"
        "var col=gradeColor(g),circ=2*Math.PI*50,off=((1-s/100)*circ).toFixed(3);"
        "var targetsH=c.targets&&c.targets.length"
        "?\"<ul class='target-list'>\"+c.targets.map(function(t){return\"<li><span class='target-host'>\"+esc(t.host||t.url||t)+\"</span><span class='status-dot \"+(t.status==='up'?'dot-online':'dot-danger')+\"'></span></li>\";}).join('')+\"</ul>\""
        ":\"<p style='color:var(--muted);font-size:13px'>No targets registered.</p>\";"
        "var sslH=c.ssl_certs&&c.ssl_certs.length"
        "?\"<div class='ssl-timeline'>\"+c.ssl_certs.map(sslItemHtml).join('')+\"</div>\""
        ":\"<p style='color:var(--muted);font-size:13px'>No SSL certificate data.</p>\";"
        "var alertsH=c.alerts&&c.alerts.length"
        "?c.alerts.slice(0,20).map(alertItemHtml).join('')"
        ":\"<p style='color:var(--muted);font-size:13px'>No recent alerts.</p>\";"
        "var reportsH=c.reports&&c.reports.length"
        "?c.reports.map(function(r){var tp=(r.type||'summary').toLowerCase();var cls=tp.indexOf('pdf')>=0?'type-pdf':tp.indexOf('html')>=0?'type-html':'type-summary';"
        "return\"<div class='report-link'><span class='report-type \"+cls+\"'>\"+tp.toUpperCase()+\"</span><a href='\"+esc(r.url||'#')+\"'>\"+esc(r.name||r.title||'Report')+\"</a><span style='font-size:11px;color:var(--muted)'>\"+esc(r.date||'')+\"</span></div>\";}).join('')"
        ":\"<p style='color:var(--muted);font-size:13px'>No reports available.</p>\";"
        "var br=c.risk_breakdown||{};"
        "var fp=Math.min(((br.findings||{}).score_contribution||0),100);"
        "var pp=Math.min(((br.open_ports||{}).score_contribution||0),100);"
        "var sp=Math.min(((br.ssl_issues||{}).score_contribution||0),100);"
        "var ap=Math.min(((br.recent_alerts||{}).score_contribution||0),100);"
        "var bar=\"<div class='breakdown-bar'><div class='breakdown-seg' style='flex:\"+fp+\";background:var(--red)'></div><div class='breakdown-seg' style='flex:\"+pp+\";background:var(--orange)'></div><div class='breakdown-seg' style='flex:\"+sp+\";background:var(--yellow)'></div><div class='breakdown-seg' style='flex:\"+ap+\";background:var(--accent)'></div></div>\";"
        "var details=\"<div style='margin-top:16px'>"
        "<div class='detail-row'><span class='label'>Critical findings</span><span class='value'>\"+((br.findings||{}).critical||0)+\" critical, \"+((br.findings||{}).high||0)+\" high, \"+((br.findings||{}).medium||0)+\" medium</span></div>"
        "<div class='detail-row'><span class='label'>Open ports</span><span class='value'>\"+((br.open_ports||{}).count||0)+\" open ports</span></div>"
        "<div class='detail-row'><span class='label'>SSL issues</span><span class='value'>\"+((br.ssl_issues||{}).count||0)+\" issues</span></div>"
        "<div class='detail-row'><span class='label'>Recent alerts (30d)</span><span class='value'>\"+((br.recent_alerts||{}).count||0)+\" alerts</span></div></div>\";"
        "var nCrit=0;if(c.findings)for(var i=0;i<c.findings.length;i++)if(c.findings[i].severity==='critical')nCrit++;"
        "return\"<a href='/' class='back-link'>&#8592; Back to Overview</a>\""
        "+'<div style=\"display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:20px\">"
        "<div><h2 style=\"font-size:20px;font-weight:700;margin-bottom:4px\">'+esc(c.name)+'</h2>"
        "<p style=\"color:var(--muted);font-size:13px\">'+esc(c.contact_email||'')+'</p></div>"
        "<span class=\"risk-badge risk-\"+g+\"\">'+s+' / 100 \\u2014 '+g.toUpperCase()+'</span></div>'"
        "+'<div class=\"tab-bar\">"
        "<button class=\"tab-btn active\" id=\"tab-btn-summary\" onclick=\"showTab(\\x27summary\\x27)\">Summary</button>"
        "<button class=\"tab-btn\" id=\"tab-btn-targets\" onclick=\"showTab(\\x27targets\\x27)\">Targets</button>"
        "<button class=\"tab-btn\" id=\"tab-btn-ssl\" onclick=\"showTab(\\x27ssl\\x27)\">SSL</button>"
        "<button class=\"tab-btn\" id=\"tab-btn-alerts\" onclick=\"showTab(\\x27alerts\\x27)\">Alerts</button>"
        "<button class=\"tab-btn\" id=\"tab-btn-reports\" onclick=\"showTab(\\x27reports\\x27)\">Reports</button>"
        "<button class=\"tab-btn\" id=\"tab-btn-risk\" onclick=\"showTab(\\x27risk\\x27)\">Risk Breakdown</button></div>'"
        "+'<div id=\"tab-summary\" class=\"tab-panel active\">"
        "<div class=\"grid-2\">"
        "<div class=\"card\"><div class=\"section-title\">Last Scan</div>"
        "<div class=\"detail-row\"><span class=\"label\">Date</span><span class=\"value\">'+esc(c.last_scan_date||'Never')+'</span></div>"
        "<div class=\"detail-row\"><span class=\"label\">Targets</span><span class=\"value\">'+(c.targets?c.targets.length:0)+'</span></div>"
        "<div class=\"detail-row\"><span class=\"label\">Open ports</span><span class=\"value\">'+(c.open_ports?c.open_ports.length:0)+'</span></div>"
        "<div class=\"detail-row\"><span class=\"label\">Critical findings</span><span class=\"value\" style=\"color:'+(nCrit?'var(--red)':'inherit')+'\">'+nCrit+'</span></div>"
        "<div class=\"detail-row\"><span class=\"label\">SSL certs tracked</span><span class=\"value\">'+(c.ssl_certs?c.ssl_certs.length:0)+'</span></div></div>"
        "<div class=\"card\" style=\"display:flex;flex-direction:column;align-items:center;justify-content:center\">"
        "<div class=\"section-title\" style=\"align-self:flex-start\">Overall Risk Score</div>"
        "<div class=\"gauge-wrap\">"
        "<svg class=\"gauge-svg\" width=\"120\" height=\"120\" viewBox=\"0 0 120 120\">"
        "<circle class=\"gauge-bg\" cx=\"60\" cy=\"60\" r=\"50\"/>"
        "<circle class=\"gauge-fill\" cx=\"60\" cy=\"60\" r=\"50\" stroke=\"'+col+'\" stroke-dasharray=\"'+circ+'\" stroke-dashoffset=\"'+off+'\"/>"
        "</svg>"
        "<span style=\"font-size:28px;font-weight:700;color:'+col+';margin-top:-70px;position:relative;top:-10px\">'+s+'</span>"
        "<span style=\"font-size:12px;color:var(--muted)\">out of 100 \\u2014 '+g.toUpperCase()+'</span></div></div></div></div>'"
        "+'<div id=\"tab-targets\" class=\"tab-panel\"><div class=\"card\"><div class=\"section-title\">Monitored Targets <span class=\"badge\">'+(c.targets?c.targets.length:0)+'</span></div>'+targetsH+'</div></div>'"
        "+'<div id=\"tab-ssl\" class=\"tab-panel\"><div class=\"card\"><div class=\"section-title\">SSL Certificate Timeline</div>'+sslH+'</div></div>'"
        "+'<div id=\"tab-alerts\" class=\"tab-panel\"><div class=\"card\"><div class=\"section-title\">Recent Alerts <span class=\"badge\">'+(c.alerts?c.alerts.length:0)+'</span></div>'+alertsH+'</div></div>'"
        "+'<div id=\"tab-reports\" class=\"tab-panel\"><div class=\"card\"><div class=\"section-title\">Available Reports</div>'+reportsH+'</div></div>'"
        "+'<div id=\"tab-risk\" class=\"tab-panel\"><div class=\"card\"><div class=\"section-title\">Risk Score Breakdown</div>'+bar"
        "+'<div class=\"breakdown-legend\"><span><span class=\"dot\" style=\"background:var(--red)\"></span>Findings ('+fp+'%)</span>'"
        "+'<span><span class=\"dot\" style=\"background:var(--orange)\"></span>Ports ('+pp+'%)</span>'"
        "+'<span><span class=\"dot\" style=\"background:var(--yellow)\"></span>SSL ('+sp+'%)</span>'"
        "+'<span><span class=\"dot\" style=\"background:var(--accent)\"></span>Alerts ('+ap+'%)</span></div>'+details+'</div></div>';"
        "}"
        "function showTab(n){"
        "var btns=document.querySelectorAll('.tab-btn');for(var i=0;i<btns.length;i++)btns[i].classList.remove('active');"
        "var pans=document.querySelectorAll('.tab-panel');for(var i=0;i<pans.length;i++)pans[i].classList.remove('active');"
        "document.getElementById('tab-'+n).classList.add('active');"
        "document.getElementById('tab-btn-'+n).classList.add('active');"
        "}"
        "document.getElementById('logout-btn').addEventListener('click',function(){"
        "sessionStorage.removeItem('eq_tok');window.location.href='/login';});"
        "function tok(){return sessionStorage.getItem('eq_tok')||'';}"
        "function api(m,path,body){"
        "var t=tok(),o={method:m,headers:{'Authorization':'Bearer '+t,'Content-Type':'application/json'}};if(body)o.body=JSON.stringify(body);"
        "return fetch(path,o).then(function(r){if(r.status===401){window.location.href='/login';throw'auth';}return r;});"
        "}"
        "renderPage();"
        "setInterval(function(){api('GET','/api/clients').then(function(r){return r.json();}).then(function(d){"
        "CLIENTS.length=0;for(var i=0;i<(d.clients||d).length;i++)CLIENTS.push((d.clients||d)[i]);renderPage();});},30000);"
        "</script>"
    )


def build_index_html(clients):
    cj = json.dumps(clients, default=str)
    js = build_js(cj)
    return (
        "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1.0'>"
        "<title>EdgeIQ Client Portal</title>"
        "<style>" + CSS + "</style></head><body>"
        "<header>"
        "<div class='logo'>Edge<span>IQ</span> <span style='color:var(--muted);font-weight:400;font-size:14px'>Client Portal</span></div>"
        "<nav><a href='/' class='active'>Overview</a></nav>"
        "<button class='logout-btn' id='logout-btn'>Sign Out</button>"
        "</header>"
        "<div class='container' id='main-content'><div class='spinner'></div></div>"
        + js +
        "</body></html>"
    )


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        sys.stderr.write("[EdgeIQ] " + (fmt % args) + "\n")

    def do_GET(self):
        p = urlparse(self.path).path

        if p == "/login":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(LOGIN_HTML.encode())
            return

        if p == "/api/me":
            if not require_auth(self):
                return
            send_json(self, 200, {"ok": True})
            return

        if p == "/api/clients":
            if not require_auth(self):
                return
            send_json(self, 200, {"clients": list_clients()})
            return

        m = re.match(r"^/api/clients/([^/]+)$", p)
        if m:
            if not require_auth(self):
                return
            c = load_client(m.group(1))
            if not c:
                send_json(self, 404, {"error": "Client not found"})
                return
            send_json(self, 200, c)
            return

        if p == "/api/alerts":
            if not require_auth(self):
                return
            all_a = []
            for c in list_clients():
                for a in c.get("alerts", []):
                    a = dict(a)
                    a["_client_id"] = c.get("client_id", "")
                    a["_client_name"] = c.get("name", "")
                    all_a.append(a)
            all_a.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
            send_json(self, 200, {
                "total": len(all_a),
                "by_severity": {
                    "critical": sum(1 for a in all_a if a.get("severity", "").lower() == "critical"),
                    "high": sum(1 for a in all_a if a.get("severity", "").lower() == "high"),
                    "medium": sum(1 for a in all_a if a.get("severity", "").lower() == "medium"),
                    "low": sum(1 for a in all_a if a.get("severity", "").lower() == "low"),
                    "info": sum(1 for a in all_a if a.get("severity", "").lower() == "info"),
                },
                "alerts": all_a[:100],
            })
            return

        if p == "/api/health":
            send_json(self, 200, {"status": "ok", "version": "1.0.0"})
            return

        if p in ("/", "/index.html"):
            if not require_auth(self):
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(build_index_html(list_clients()).encode())
            return

        self.send_error(404, "Not found")

    def do_POST(self):
        p = urlparse(self.path).path

        if p == "/api/clients":
            if not require_auth(self):
                return
            try:
                data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            except json.JSONDecodeError:
                send_json(self, 400, {"error": "Invalid JSON"})
                return
            name = (data.get("name") or "").strip()
            if not name:
                send_json(self, 400, {"error": "Client name is required"})
                return
            cid = data.get("client_id") or next_client_id()
            if load_client(cid):
                send_json(self, 409, {"error": "Client already exists", "client_id": cid})
                return
            now = datetime.datetime.utcnow().isoformat() + "Z"
            save_client(cid, {
                "client_id": cid, "name": name,
                "contact_email": data.get("contact_email", ""),
                "targets": data.get("targets", []),
                "findings": [], "open_ports": [], "ssl_certs": [],
                "alerts": [], "reports": [],
                "risk_score": 0, "risk_grade": "low", "risk_breakdown": {},
                "last_scan_date": None, "last_activity": now, "created_at": now,
            })
            send_json(self, 201, {"ok": True, "client_id": cid})
            return

        m = re.match(r"^/api/clients/([^/]+)/scan$", p)
        if m:
            if not require_auth(self):
                return
            cid = m.group(1)
            c = load_client(cid)
            if not c:
                send_json(self, 404, {"error": "Client not found"})
                return
            try:
                scan = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            except json.JSONDecodeError:
                send_json(self, 400, {"error": "Invalid JSON"})
                return
            self._apply_scan(c, scan)
            c = update_client_risk(cid)
            send_json(self, 200, {"ok": True, "client_id": cid,
                                   "risk_score": c["risk_score"],
                                   "risk_grade": c["risk_grade"]})
            return

        m2 = re.match(r"^/api/clients/([^/]+)$", p)
        if m2:
            if not require_auth(self):
                return
            cid = m2.group(1)
            try:
                data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            except json.JSONDecodeError:
                send_json(self, 400, {"error": "Invalid JSON"})
                return
            c = load_client(cid)
            now = datetime.datetime.utcnow().isoformat() + "Z"
            if c:
                c["name"] = data.get("name", c["name"])
                c["contact_email"] = data.get("contact_email", c["contact_email"])
                for k in ("targets", "findings", "open_ports", "ssl_certs", "alerts", "reports"):
                    if k in data:
                        c[k] = data[k]
                c["last_activity"] = now
                update_client_risk(cid)
                send_json(self, 200, {"ok": True, "client_id": cid})
            else:
                update_client_risk(cid)
                send_json(self, 201, {"ok": True, "client_id": cid})
            return

        self.send_error(404, "Not found")

    def _apply_scan(self, c, scan):
        now = datetime.datetime.utcnow().isoformat() + "Z"

        if "target" in scan:
            t = scan["target"]
            if not any(x.get("host") == t or x == t for x in c.get("targets", [])):
                c.setdefault("targets", []).append({"host": t, "status": "pending"})

        if "targets" in scan:
            existing = {x.get("host") or x for x in c.get("targets", [])}
            for t in scan["targets"]:
                h = t.get("host") or t.get("url") or t
                if h not in existing:
                    c.setdefault("targets", []).append({"host": h, "status": t.get("status", "pending")})

        c["last_scan_date"] = scan.get("scan_date") or scan.get("timestamp") or now[:10]

        if "open_ports" in scan:
            existing = {p.get("port") for p in c.get("open_ports", [])}
            for p in scan["open_ports"]:
                if p.get("port") not in existing:
                    c.setdefault("open_ports", []).append(p)

        if "ssl_certs" in scan:
            existing = {(x.get("host"), x.get("fingerprint", "")) for x in c.get("ssl_certs", [])}
            for cert in scan["ssl_certs"]:
                key = (cert.get("host"), cert.get("fingerprint", ""))
                if key not in existing:
                    c.setdefault("ssl_certs", []).append(cert)

        if "findings" in scan:
            for f in scan["findings"]:
                fp = f.get("fingerprint") or hashlib.md5(
                    (str(f.get("title", "")) + str(f.get("severity", ""))).encode()
                ).hexdigest()
                if not any(x.get("fingerprint") == fp for x in c.get("findings", [])):
                    c.setdefault("findings", []).append(f)

        if "alerts" in scan:
            for a in scan["alerts"]:
                a = dict(a)
                a["timestamp"] = a.get("timestamp") or now
                c.setdefault("alerts", []).insert(0, a)
            c["alerts"] = c["alerts"][:500]

        if "reports" in scan:
            existing = {r.get("url") or r.get("name") for r in c.get("reports", [])}
            for r in scan["reports"]:
                k = r.get("url") or r.get("name")
                if k and k not in existing:
                    c.setdefault("reports", []).append(r)

        c["last_activity"] = now
        save_client(c["client_id"], c)


# ---------------------------------------------------------------------------
# One-shot mode
# ---------------------------------------------------------------------------
def oneshot(path):
    with open(path) as f:
        data = json.load(f)
    for cd in (data if isinstance(data, list) else [data]):
        cid = cd.get("client_id") or (cd.get("name", "").lower().replace(" ", "-")[:20])
        c = load_client(cid)
        if not c:
            now = datetime.datetime.utcnow().isoformat() + "Z"
            c = {"client_id": cid, "name": cd.get("name", cid),
                 "contact_email": cd.get("contact_email", ""),
                 "targets": [], "findings": [], "open_ports": [],
                 "ssl_certs": [], "alerts": [], "reports": [],
                 "risk_score": 0, "risk_grade": "low", "risk_breakdown": {},
                 "last_scan_date": None, "last_activity": now, "created_at": now}
        h = object.__new__(Handler)
        h.rfile = type("F", (), {"read": lambda s, n: b""})()
        h.wfile = type("F", (), {"write": lambda s, d: None})()
        h.headers = type("F", (), {"get": lambda s, k: ""})()
        h.send_response = lambda s, code: None
        h.send_header = lambda s, k, v: None
        h.end_headers = lambda s: None
        h._apply_scan(c, cd)
        update_client_risk(cid)
        print("[EdgeIQ] Updated: " + cid)
    print("[EdgeIQ] One-shot complete.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    import argparse
    a = argparse.ArgumentParser(description="EdgeIQ Client Dashboard")
    a.add_argument("--oneshot", metavar="FILE", help="Load scan data from JSON file and exit")
    a.add_argument("--port", type=int, default=PORT, help="HTTP port (default: %d)" % PORT)
    args = a.parse_args()

    tok = get_token()
    if not os.getenv("AUTH_TOKEN"):
        print("[EdgeIQ] AUTH_TOKEN not set -- generated: " + tok)
        print("[EdgeIQ] Save this token! Set AUTH_TOKEN env var to persist it.")
    else:
        print("[EdgeIQ] Dashboard starting on port " + str(args.port))

    os.makedirs(clients_dir(), exist_ok=True)

    if args.oneshot:
        oneshot(args.oneshot)
        return

    srv = HTTPServer(("0.0.0.0", args.port), Handler)
    print("[EdgeIQ] Dashboard: http://localhost:" + str(args.port) + "/")
    print("[EdgeIQ] Login:    http://localhost:" + str(args.port) + "/login")
    print("[EdgeIQ] Health:   http://localhost:" + str(args.port) + "/api/health")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[EdgeIQ] Shutting down.")
        srv.server_close()


if __name__ == "__main__":
    main()
