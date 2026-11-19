#!/usr/bin/env python3
"""
NullShadow v4.0 — Defensive Monitoring Dashboard (brief Section 6.3)

A lightweight, READ-ONLY web dashboard over the existing SQLite database.
It does NOT run scans or duplicate scanning logic — it is purely a reporting
layer on top of data produced by the CLI (`python3 main.py --monitor <target>`).

Run separately:   python3 dashboard.py
Then open:        http://127.0.0.1:8077   (binds to localhost only)

Views:
  1. Posture score over time per target  (line chart, Chart.js via CDN)
  2. Findings count by severity           (bar chart)
  3. Recent monitoring runs               (table with ALERT/OK + risk_delta)
  4. Drill-down into a finding            (/finding/<id> shows its remediation block)
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from flask import Flask, request, render_template_string, abort

from null_db.db import ScanDatabase
from modules.intel.risk_score import severity_breakdown, calculate_posture_score

app = Flask(__name__)

# Bind to localhost only — this is a local reporting layer, not a control plane.
HOST = "127.0.0.1"
PORT = int(os.getenv("NULLSHADOW_DASHBOARD_PORT", "8077"))


def _db():
    # One short-lived connection per request (read-only usage).
    return ScanDatabase()


def _distinct_targets(db):
    cur = db.conn.execute(
        "SELECT DISTINCT target FROM scans WHERE target IS NOT NULL ORDER BY target")
    return [r["target"] for r in cur.fetchall()]


INDEX_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NullShadow — Defensive Monitoring Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
  <style>
    body { background:#0d0d0f; color:#e6e6e6; font-family:-apple-system,Segoe UI,Roboto,sans-serif; margin:0; padding:0 0 40px; }
    header { background:linear-gradient(90deg,#1a0000,#000); padding:18px 28px; border-bottom:2px solid #ff2222; }
    h1 { margin:0; font-size:20px; color:#ff4444; letter-spacing:2px; }
    .sub { color:#888; font-size:12px; }
    .wrap { max-width:1100px; margin:0 auto; padding:20px 28px; }
    .grid { display:grid; grid-template-columns:1fr 1fr; gap:22px; }
    .card { background:#16161a; border:1px solid #262630; border-radius:10px; padding:18px; }
    .card h2 { font-size:14px; color:#00aaff; margin:0 0 12px; text-transform:uppercase; letter-spacing:1px; }
    form { margin:0 0 16px; }
    select, button { background:#16161a; color:#e6e6e6; border:1px solid #333; border-radius:6px; padding:7px 10px; font-size:13px; }
    table { width:100%; border-collapse:collapse; font-size:13px; }
    th,td { text-align:left; padding:8px 10px; border-bottom:1px solid #24242c; }
    th { color:#888; font-weight:600; }
    .alert { color:#ff4444; font-weight:700; }
    .ok { color:#33cc66; font-weight:700; }
    .pill { padding:2px 8px; border-radius:10px; font-size:11px; }
    a { color:#00aaff; text-decoration:none; }
    a:hover { text-decoration:underline; }
    .muted { color:#777; font-size:12px; }
    .score { font-size:30px; font-weight:800; }
    nav.ns { display:flex; flex-wrap:wrap; gap:6px; padding:12px 28px; background:#111; border-bottom:1px solid #222; }
    nav.ns a { color:#cfd8e3; background:#1a1a20; border:1px solid #2a2a33; padding:6px 12px; border-radius:16px; font-size:12px; }
    nav.ns a:hover { border-color:#cc0000; color:#fff; text-decoration:none; }
    nav.ns a.active { background:#cc0000; border-color:#cc0000; color:#fff; }
    .kpis { display:grid; grid-template-columns:repeat(3,1fr); gap:16px; margin:0 0 22px; }
    .kpi { background:#16161a; border:1px solid #262630; border-radius:10px; padding:16px; text-align:center; }
    .kpi .num { font-size:34px; font-weight:800; }
    .kpi .lbl { color:#888; font-size:11px; text-transform:uppercase; letter-spacing:1px; margin-top:4px; }
  </style>
</head>
<body>
  <header>
    <h1>🛡 NULLSHADOW · DEFENSIVE MONITORING</h1>
    <div class="sub">Read-only reporting layer · localhost only · data from <code>main.py --monitor</code></div>
  </header>
  <nav class="ns">
    <a href="/{{ ('?target=' ~ target) if target else '' }}" class="active">Overview</a>
    <a href="/timemachine?target={{target}}">🕰 Time Machine</a>
    <a href="/threatintel?target={{target}}">📡 Threat Intel</a>
    <a href="/prediction?target={{target}}">🔮 Prediction</a>
    <a href="/dna?target={{target}}">🧬 Security DNA</a>
    <a href="/compliance?target={{target}}">📜 Compliance</a>
    <a href="/sentinel">👁 Sentinel</a>
    <a href="/effectiveness?target={{target}}">🔁 Remediation</a>
  </nav>
  <div class="wrap">
    <form method="get" action="/">
      <label class="muted">Target:&nbsp;</label>
      <select name="target" onchange="this.form.submit()">
        {% for t in targets %}
          <option value="{{t}}" {% if t==target %}selected{% endif %}>{{t}}</option>
        {% endfor %}
      </select>
      <noscript><button type="submit">Go</button></noscript>
    </form>

    {% if target %}
    <div class="card" style="margin-bottom:22px;">
      <h2>Current posture — {{target}}</h2>
      <span class="score" style="color:{{ '#33cc66' if latest_score>=70 else '#ffaa00' if latest_score>=40 else '#ff4444' }}">{{latest_score}}</span>
      <span class="muted">/ 100 &nbsp;({{ findings|length }} findings)</span>
    </div>
    {% endif %}

    {% if target %}
    <div class="kpis">
      <div class="kpi"><div class="num" data-count="{{latest_score}}" style="color:{{ '#33cc66' if latest_score>=70 else '#ffaa00' if latest_score>=40 else '#ff4444' }}">0</div><div class="lbl">Posture Score</div></div>
      <div class="kpi"><div class="num" data-count="{{critical_count}}" style="color:#ff4444">0</div><div class="lbl">Active Critical</div></div>
      <div class="kpi"><div class="num" data-count="{{days_since_scan}}" style="color:#00aaff">0</div><div class="lbl">Days Since Last Scan</div></div>
    </div>
    {% endif %}

    <div class="grid">
      <div class="card">
        <h2>Posture over time</h2>
        <canvas id="postureChart" height="180"></canvas>
      </div>
      <div class="card">
        <h2>Findings by severity</h2>
        <canvas id="sevChart" height="180"></canvas>
      </div>
    </div>

    <div class="card" style="margin-top:22px;">
      <h2>Recent monitoring runs</h2>
      <table>
        <thead><tr><th>Scan</th><th>Target</th><th>Date</th><th>Posture</th><th>Δ Risk</th><th>Status</th></tr></thead>
        <tbody>
        {% for r in runs %}
          <tr>
            <td>#{{r['id']}}</td>
            <td>{{r['target']}}</td>
            <td class="muted">{{r['timestamp'][:16]}}</td>
            <td>{{r['posture_score']}}</td>
            <td>{{ ('+' ~ r['risk_delta']) if (r['risk_delta'] is not none and r['risk_delta']>0) else (r['risk_delta'] if r['risk_delta'] is not none else '—') }}</td>
            <td class="{{ 'alert' if r['alert_status']=='ALERT' else 'ok' }}">{{r['alert_status'] or '—'}}</td>
          </tr>
        {% endfor %}
        {% if not runs %}
          <tr><td colspan="6" class="muted">No monitoring runs yet. Run <code>python3 main.py --monitor &lt;target&gt;</code>.</td></tr>
        {% endif %}
        </tbody>
      </table>
    </div>

    <div class="card" style="margin-top:22px;">
      <h2>Findings {{ ('— ' ~ target) if target else '' }}</h2>
      <table>
        <thead><tr><th>ID</th><th>Severity</th><th>Type</th><th>Title</th><th>CVE</th><th></th></tr></thead>
        <tbody>
        {% for f in findings[-40:] %}
          <tr>
            <td>{{f['id']}}</td>
            <td>{{f['severity']}}</td>
            <td class="muted">{{f['finding_type']}}</td>
            <td>{{f['title'][:60]}}</td>
            <td class="muted">{{ ', '.join(f['cve_ids']) }}</td>
            <td><a href="/finding/{{f['id']}}">remediation →</a></td>
          </tr>
        {% endfor %}
        {% if not findings %}
          <tr><td colspan="6" class="muted">No findings stored for this target yet.</td></tr>
        {% endif %}
        </tbody>
      </table>
    </div>
  </div>

  <script>
    const postureData = {{ posture_json|safe }};
    const sevData = {{ sev_json|safe }};
    new Chart(document.getElementById('postureChart'), {
      type:'line',
      data:{ labels: postureData.labels,
        datasets:[{ label:'Posture score', data: postureData.scores,
          borderColor:'#00aaff', backgroundColor:'rgba(0,170,255,.15)', tension:.25, fill:true }] },
      options:{ animation:{duration:800, easing:'easeOutQuart'},
        scales:{ y:{ min:0, max:100, ticks:{color:'#888'} }, x:{ ticks:{color:'#888'} } },
        plugins:{ legend:{ labels:{ color:'#ccc' } } } }
    });
    new Chart(document.getElementById('sevChart'), {
      type:'bar',
      data:{ labels: Object.keys(sevData),
        datasets:[{ label:'Findings', data: Object.values(sevData),
          backgroundColor:['#ff2222','#ff7711','#ffcc00','#33aaff','#777'] }] },
      options:{ animation:{duration:800, easing:'easeOutQuart'},
        scales:{ y:{ beginAtZero:true, ticks:{color:'#888'} }, x:{ ticks:{color:'#888'} } },
        plugins:{ legend:{ display:false } } }
    });
    // KPI count-up (vanilla JS, no library)
    document.querySelectorAll('.kpi .num[data-count]').forEach(function(el){
      var target = parseInt(el.getAttribute('data-count')) || 0, cur = 0,
          step = Math.max(1, Math.round(target/40));
      var iv = setInterval(function(){
        cur += step; if (cur >= target){ cur = target; clearInterval(iv); }
        el.textContent = cur;
      }, 18);
    });
  </script>
</body>
</html>
"""

FINDING_HTML = """
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Remediation — {{block.title}}</title>
<style>
  body { background:#0d0d0f; color:#e6e6e6; font-family:-apple-system,Segoe UI,Roboto,sans-serif; }
  .wrap { max-width:820px; margin:0 auto; padding:30px; }
  h1 { color:#33cc66; font-size:20px; }
  h2 { color:#00aaff; font-size:14px; text-transform:uppercase; letter-spacing:1px; margin-top:22px; }
  pre { background:#101014; border:1px solid #262630; border-radius:8px; padding:14px; overflow:auto; color:#7CFC9B; }
  .meta { color:#aaa; }
  a { color:#00aaff; } li { margin:4px 0; }
  .ref { color:#ffaa00; }
</style></head><body><div class="wrap">
  <a href="/">← back to dashboard</a>
  <h1>🛡 Guided Remediation</h1>
  <p><b>{{block.title}}</b></p>
  <p class="meta">{{block.severity_context}}<br>{{block.cwe}} · {{block.owasp}}</p>
  <h2>Explanation</h2><p>{{block.explanation}}</p>
  {% if block.ai_explanation %}<h2>AI analysis</h2><p>{{block.ai_explanation}}</p>{% endif %}
  <h2>Remediation steps</h2>
  <ol>{% for s in block.remediation_steps %}<li>{{s}}</li>{% endfor %}</ol>
  <h2>Secure pattern (generic)</h2>
  <pre>{{block.secure_snippet}}</pre>
  {% if block.exploit_reference %}<p class="ref">{{block.exploit_reference}}</p>{% endif %}
</div></body></html>
"""


@app.route("/")
def index():
    db = _db()
    try:
        targets = _distinct_targets(db)
        target = request.args.get("target") or (targets[0] if targets else None)

        findings = db.get_findings(target=target) if target else []
        posture_rows = db.get_posture_history(target) if target else []
        posture_json = {
            "labels": [str(r["timestamp"])[:16] for r in posture_rows],
            "scores": [r["posture_score"] for r in posture_rows],
        }
        sev_json = severity_breakdown(findings)
        latest_score = calculate_posture_score(findings) if findings else 100
        runs = [dict(r) for r in db.get_monitor_runs()]

        # KPI values (Phase M count-up cards)
        critical_count = sum(1 for f in findings
                             if (f.get("severity") or "").upper() in ("CRITICAL", "HIGH"))
        days_since_scan = 0
        scans = db.get_scans_for_target(target) if target else []
        if scans:
            from datetime import datetime as _dt
            try:
                last = _dt.fromisoformat(str(scans[0]["timestamp"]))
                days_since_scan = max(0, (_dt.now() - last).days)
            except Exception:
                days_since_scan = 0

        import json as _json
        return render_template_string(
            INDEX_HTML, targets=targets, target=target, findings=findings,
            runs=runs, latest_score=latest_score,
            critical_count=critical_count, days_since_scan=days_since_scan,
            posture_json=_json.dumps(posture_json), sev_json=_json.dumps(sev_json))
    finally:
        db.close()


@app.route("/finding/<int:finding_id>")
def finding(finding_id):
    db = _db()
    try:
        cur = db.conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
        row = cur.fetchone()
        if not row:
            abort(404)
        f = db._row_to_finding(row)
        from modules.intel.remediation import generate_remediation
        block = generate_remediation(f, use_ai=False)
        return render_template_string(FINDING_HTML, block=block)
    finally:
        db.close()


# ══════════════════════════════════════════════════════════════
#  v5.0 views (Phase M) — each reads data from the v5 modules and
#  renders a focused dark-themed page. All read-only.
# ══════════════════════════════════════════════════════════════

_BASE_HEAD = """
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NullShadow — {title}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
 body{{background:#0d0d0d;color:#e6e6e6;font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:0 0 50px;}}
 header{{background:linear-gradient(90deg,#1a0000,#000);padding:16px 28px;border-bottom:2px solid #cc0000;}}
 h1{{margin:0;font-size:19px;color:#ff4444;letter-spacing:1px;}}
 .wrap{{max-width:1100px;margin:0 auto;padding:22px 28px;}}
 .card{{background:#16161a;border:1px solid #262630;border-radius:10px;padding:18px;margin-bottom:20px;}}
 h2{{font-size:14px;color:#00aaff;margin:0 0 12px;text-transform:uppercase;letter-spacing:1px;}}
 table{{width:100%;border-collapse:collapse;font-size:13px;}}
 th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #24242c;}}
 th{{color:#888;}} a{{color:#00aaff;text-decoration:none;}} a:hover{{text-decoration:underline;}}
 .red{{color:#ff4444;font-weight:700;}} .yellow{{color:#ffaa00;font-weight:700;}} .green{{color:#33cc66;font-weight:700;}}
 .muted{{color:#777;font-size:12px;}} .big{{font-size:26px;font-weight:800;}}
 .pill{{padding:2px 9px;border-radius:12px;font-size:11px;background:#222;}}
 .bar{{height:14px;border-radius:7px;background:#cc0000;}}
</style></head><body>
<header><h1>🛡 NULLSHADOW · {title}</h1></header>
<div class="wrap"><p><a href="/?target={target}">← back to overview</a>&nbsp; <span class="muted">target: {target}</span></p>
"""
_BASE_TAIL = "</div></body></html>"


def _esc(s):
    from markupsafe import escape
    return str(escape(s))


def _needs_target(target, title):
    if target:
        return None
    return (_BASE_HEAD.format(title=title, target="") +
            '<div class="card"><p class="muted">Add <code>?target=example.com</code> '
            'to the URL (or pick a target on the overview page).</p></div>' + _BASE_TAIL)


@app.route("/timemachine")
def timemachine():
    from modules.intel.time_machine import exposure_analysis, get_time_machine_chart_data
    db = _db()
    try:
        target = request.args.get("target")
        miss = _needs_target(target, "Time Machine")
        if miss:
            return miss
        res = exposure_analysis(db, target)
        chart = get_time_machine_chart_data(db, target)
        rows = ""
        for e in res["exposures"]:
            cls = e["class"]
            col = "red" if cls in ("CRITICAL_EXPOSURE", "PROLONGED") else "yellow" if cls == "HIGH_EXPOSURE" else "green"
            rows += (f"<tr><td>{_esc(e['cve_id'])}</td><td>{_esc(e['severity'])}</td>"
                     f"<td>{_esc(e['exposure_start'])}</td><td class='{col}'>{e['days_exposed']}d</td>"
                     f"<td><span class='pill {col}'>{cls}</span></td></tr>")
        if not rows:
            rows = "<tr><td colspan=5 class='muted'>No CVE exposures with a known window yet.</td></tr>"
        import json as _json
        body = (_BASE_HEAD.format(title="Time Machine", target=_esc(target)) +
                '<div class="card"><h2>Exposure timeline</h2><canvas id="tm" height="160"></canvas></div>'
                '<div class="card"><h2>Days exposed per CVE</h2><table>'
                '<tr><th>CVE</th><th>Severity</th><th>Exposure start</th><th>Days</th><th>Class</th></tr>'
                + rows + '</table></div>'
                '<script>new Chart(document.getElementById("tm"),{type:"bar",'
                'data:{labels:' + _json.dumps(chart["labels"]) + ',datasets:[{label:"Days exposed",'
                'data:' + _json.dumps(chart["days"]) + ',backgroundColor:"#cc0000"}]},'
                'options:{indexAxis:"y",animation:{duration:800,easing:"easeOutQuart"},'
                'plugins:{legend:{display:false}},scales:{x:{ticks:{color:"#888"}},y:{ticks:{color:"#888"}}}}});</script>'
                + _BASE_TAIL)
        return body
    finally:
        db.close()


@app.route("/threatintel")
def threatintel():
    from modules.intel.threat_feeds import ThreatIntelChecker
    db = _db()
    try:
        target = request.args.get("target")
        miss = _needs_target(target, "Threat Intel")
        if miss:
            return miss
        res = ThreatIntelChecker(db).check_target(target, db.get_findings(target=target))
        status = res["status"]
        col = "red" if status == "CRITICAL" else "yellow" if status == "ALERT" else "green"
        kev = ""
        for e in res["kev_matches"]:
            kev += (f"<tr><td class='red'>{_esc(e['cve_id'])}</td>"
                    f"<td>{_esc(e.get('vendor',''))} {_esc(e.get('product',''))}</td>"
                    f"<td>{_esc(e.get('date_added',''))}</td><td>{_esc(e.get('ransomware','Unknown'))}</td></tr>")
        if not kev:
            kev = "<tr><td colspan=4 class='muted'>No CISA KEV (actively-exploited) matches.</td></tr>"
        alerts = "".join(f"<li>{_esc(a)}</li>" for a in res["alerts"]) or "<li class='muted'>No alerts.</li>"
        body = (_BASE_HEAD.format(title="Threat Intel", target=_esc(target)) +
                f'<div class="card"><h2>Status</h2><span class="big {col}">{status}</span>'
                f'<span class="muted"> &nbsp;· CISA KEV matches: {res["kev_count"]}</span></div>'
                '<div class="card"><h2>🔴 CISA KEV — actively exploited</h2><table>'
                '<tr><th>CVE</th><th>Product</th><th>Added</th><th>Ransomware</th></tr>' + kev + '</table></div>'
                '<div class="card"><h2>Alerts</h2><ul>' + alerts + '</ul></div>' + _BASE_TAIL)
        return body
    finally:
        db.close()


@app.route("/prediction")
def prediction():
    from modules.intel.attack_prediction import predict_all
    db = _db()
    try:
        target = request.args.get("target")
        miss = _needs_target(target, "Attack Prediction")
        if miss:
            return miss
        res = predict_all(target, db)
        rows = ""
        for p in res["predictions"]:
            days = p.get("days_until_weaponized", 0)
            col = "red" if days <= 7 else "yellow" if days <= 14 else "green"
            pc = "red" if p["probability"] >= 70 else "yellow" if p["probability"] >= 40 else ""
            when = "NOW" if p["status"] == "already_exploited" else f"{days}d"
            rows += (f"<tr><td>{_esc(p['cve_id'])}</td><td class='{pc}'>{p['probability']}%</td>"
                     f"<td class='{col}'>{when}</td><td>{p.get('exposure_days',0)}d</td>"
                     f"<td>{'✓' if p.get('has_public_poc') else '—'}</td><td>{_esc(p.get('severity','?'))}</td></tr>")
        if not rows:
            rows = "<tr><td colspan=6 class='muted'>No tech-matched CVEs to predict.</td></tr>"
        body = (_BASE_HEAD.format(title="Attack Prediction", target=_esc(target)) +
                '<div class="card"><h2>🔮 Cognitive attack prediction (countdown by urgency)</h2><table>'
                '<tr><th>CVE</th><th>Probability</th><th>Weaponized in</th><th>Exposure</th><th>PoC</th><th>Severity</th></tr>'
                + rows + '</table><p class="muted">Model trained on NVD→CISA KEV time-to-weaponization patterns.</p></div>'
                + _BASE_TAIL)
        return body
    finally:
        db.close()


@app.route("/dna")
def dna():
    from modules.intel.security_dna import match_breach_patterns
    db = _db()
    try:
        target = request.args.get("target")
        miss = _needs_target(target, "Security DNA")
        if miss:
            return miss
        res = match_breach_patterns(db, target)
        rows = ""
        for m in res["matches"]:
            s = m["similarity"]
            col = "red" if s >= 60 else "yellow" if s >= 35 else "green"
            rows += (f"<tr><td>{_esc(m['name'])}</td><td>{m.get('year','')}</td>"
                     f"<td class='{col}'>{s}%</td><td style='width:220px'>"
                     f"<div class='bar' style='width:{max(4,s)}%;background:"
                     f"{'#cc0000' if s>=60 else '#ffaa00' if s>=35 else '#33cc66'}'></div></td>"
                     f"<td class='muted'>{_esc('; '.join(m['factors']))}</td></tr>")
        dna_d = res["dna"]
        body = (_BASE_HEAD.format(title="Security DNA", target=_esc(target)) +
                f'<div class="card"><h2>Fingerprint</h2><p class="muted">Tech: {_esc(", ".join(dna_d["tech"][:14]))}<br>'
                f'Ports: {_esc(", ".join(str(p) for p in dna_d["ports"]))}<br>'
                f'Missing headers: {_esc(", ".join(dna_d["missing_headers"]) or "—")}<br>'
                f'CVE types: {_esc(", ".join(dna_d["cve_types"]) or "—")} · Weak TLS: {dna_d["ssl_weak"]}</p></div>'
                '<div class="card"><h2>🧬 Breach-pattern similarity</h2><table>'
                '<tr><th>Breach pattern</th><th>Year</th><th>Similarity</th><th></th><th>Matching factors</th></tr>'
                + rows + '</table></div>' + _BASE_TAIL)
        return body
    finally:
        db.close()


@app.route("/compliance")
def compliance():
    from modules.compliance.compliance_mapper import summarize, FRAMEWORKS
    db = _db()
    try:
        target = request.args.get("target")
        miss = _needs_target(target, "Compliance")
        if miss:
            return miss
        findings = db.get_findings(target=target)
        cards = ""
        for fw in FRAMEWORKS:
            s = summarize(findings, fw)
            ctrl_rows = "".join(
                f"<tr><td>{_esc(c)}</td><td>{'Continuous monitoring' if not ids else len(ids)}</td></tr>"
                for c, ids in sorted(s["coverage"].items()))
            cards += (f'<div class="card"><h2>{_esc(s["framework_name"])}</h2>'
                      f'<p><span class="big green">{s["controls_evidenced"]}</span> '
                      f'<span class="muted">controls evidenced from {s["total_findings"]} findings</span></p>'
                      f'<table><tr><th>Control</th><th>Evidence</th></tr>{ctrl_rows}</table></div>')
        body = (_BASE_HEAD.format(title="Compliance", target=_esc(target)) +
                '<div class="card"><h2>📜 Audit evidence coverage</h2>'
                '<p class="muted">Generate the full PDF from the CLI: <code>main.py</code> → [49], '
                'or MCP tool <code>compliance_report(target, framework)</code>.</p></div>'
                + cards + _BASE_TAIL)
        return body
    finally:
        db.close()


@app.route("/sentinel")
def sentinel_view():
    from modules.intel.sentinel import SentinelMode
    db = _db()
    try:
        st = SentinelMode(db).status()
        run = st["running"]
        rows = ""
        for a in st.get("recent_alerts", []):
            rows += (f"<tr><td class='red'>{_esc(a['cve_id'])}</td><td>{_esc(a['target'])}</td>"
                     f"<td>{_esc(a['matched_tech'])}</td><td>{_esc(a.get('severity','?'))}</td>"
                     f"<td>{'✓' if a.get('notification_sent') else '—'}</td></tr>")
        if not rows:
            rows = "<tr><td colspan=5 class='muted'>No Sentinel alerts yet.</td></tr>"
        body = (_BASE_HEAD.format(title="Sentinel Mode", target="") +
                f'<div class="card"><h2>Watcher</h2><span class="big {"green" if run else "red"}">'
                f'{"RUNNING" if run else "STOPPED"}</span>'
                f'<p class="muted">Targets: {_esc(", ".join(st.get("targets") or []) or "—")} · '
                f'ntfy topic: {_esc(st.get("topic") or "—")} · polls: {st.get("polls",0)}</p></div>'
                '<div class="card"><h2>👁 Recent autonomous CVE alerts</h2><table>'
                '<tr><th>CVE</th><th>Target</th><th>Matched tech</th><th>Severity</th><th>Notified</th></tr>'
                + rows + '</table></div>' + _BASE_TAIL)
        return body
    finally:
        db.close()


@app.route("/effectiveness")
def effectiveness():
    from modules.intel.remediation_tracker import verify_remediation_effectiveness
    db = _db()
    try:
        target = request.args.get("target")
        miss = _needs_target(target, "Remediation Effectiveness")
        if miss:
            return miss
        res = verify_remediation_effectiveness(db, target)
        stat_rows = ""
        for s in res.get("stats", []):
            eff = s.get("effectiveness", 0.0)
            col = "green" if eff >= 0.6 else "yellow" if eff >= 0.3 else "red"
            stat_rows += (f"<tr><td>{_esc(s['category'])}</td><td>{s.get('given_count',0)}</td>"
                          f"<td>{s.get('resolved_count',0)}</td><td class='{col}'>{round(eff*100)}%</td></tr>")
        if not stat_rows:
            stat_rows = "<tr><td colspan=4 class='muted'>No remediation stats yet.</td></tr>"
        open_rows = "".join(f"<li><b>{_esc(s['title'])}</b> ({_esc(s['category'])})<br>"
                            f"<span class='muted'>↳ {_esc(s['followup'])}</span></li>"
                            for s in res["still_open"]) or "<li class='muted'>Nothing persists after advice.</li>"
        body = (_BASE_HEAD.format(title="Remediation Effectiveness", target=_esc(target)) +
                f'<div class="card"><h2>Verification</h2><p>Checked: {res["checked"]} · '
                f'Resolved: <span class="green">{res["resolved"]}</span> · '
                f'Still open: <span class="red">{len(res["still_open"])}</span></p></div>'
                '<div class="card"><h2>🔁 Effectiveness by category</h2><table>'
                '<tr><th>Category</th><th>Given</th><th>Resolved</th><th>Effectiveness</th></tr>'
                + stat_rows + '</table></div>'
                '<div class="card"><h2>Findings persisting after advice</h2><ul>' + open_rows + '</ul></div>'
                + _BASE_TAIL)
        return body
    finally:
        db.close()


if __name__ == "__main__":
    print(f"NullShadow dashboard (read-only) → http://{HOST}:{PORT}")
    app.run(host=HOST, port=PORT, debug=False)
