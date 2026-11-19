"""
Phase I — Sentinel Mode: Autonomous CVE Watcher.

Runs as a persistent background watcher that polls the NVD "recently published"
feed every hour, cross-references each new CVE against the technology fingerprints
NullShadow has already stored for the monitored targets, and — on a match — logs a
sentinel_alert and sends a free push notification via ntfy.sh.

"Nobody triggered it. Nobody told it to scan. It just knew."

Design notes:
  * Thread is daemon=True so it never blocks process exit.
  * All network calls are best-effort; 403/429/timeouts are expected, never fatal.
  * ntfy.sh needs no account: POST to https://ntfy.sh/<topic>; the user subscribes
    to the same topic in the free ntfy mobile app.
  * The poll interval is configurable (default 3600s); tests use a tiny interval
    and a single manual poll.

Public API:
  SentinelMode(db).start(targets, interval=3600, ntfy_topic=None)
  SentinelMode(db).stop()
  SentinelMode(db).status()
  SentinelMode(db).poll_once(targets, ntfy_topic=None)   # one manual cycle
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import re
import time
import threading
from datetime import datetime, timedelta

import requests

NVD_RECENT_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NTFY_BASE = "https://ntfy.sh"
_TIMEOUT = 20


def _tokenize(value):
    out = set()
    for tok in re.split(r"[^a-z0-9.]+", str(value).lower()):
        if len(tok) >= 3 and not tok.replace(".", "").isdigit():
            out.add(tok)
    return out


class SentinelMode:
    # class-level singleton state so menu start/stop/status share one watcher
    _thread = None
    _stop_event = None
    _state = {"running": False, "targets": [], "started_at": None,
              "last_poll": None, "polls": 0, "topic": None}

    def __init__(self, db):
        self.db = db

    # ── tech fingerprint of monitored targets ──────────────────
    def _target_fingerprints(self, targets):
        """Return {target: set(tech_tokens)} from stored findings."""
        fps = {}
        for tgt in targets:
            toks = set()
            for f in self.db.get_findings(target=tgt):
                raw = f.get("raw_data") or {}
                for key in ("product", "service", "name", "server", "cms", "framework"):
                    if raw.get(key):
                        toks |= _tokenize(raw[key])
                for t in (raw.get("technologies") or []):
                    toks |= _tokenize(t)
                if (f.get("finding_type") or "") == "open_port":
                    toks |= _tokenize(f.get("title", ""))
            fps[tgt] = toks
        return fps

    # ── NVD recent feed ────────────────────────────────────────
    def _fetch_recent_cves(self, hours=1):
        """Fetch CVEs published in the last `hours` from NVD. Best-effort."""
        now = datetime.utcnow()
        start = now - timedelta(hours=hours)
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": 100,
        }
        try:
            from config.config import NVD_API_KEY
        except Exception:
            NVD_API_KEY = os.getenv("NVD_API_KEY", "")
        headers = {"Accept": "application/json", "User-Agent": "NullShadow-Sentinel/5.0"}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY
        try:
            r = requests.get(NVD_RECENT_URL, params=params, headers=headers, timeout=_TIMEOUT)
            if r.status_code != 200:
                return []
            data = r.json()
        except Exception:
            return []

        out = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cid = cve.get("id", "")
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            sev = "UNKNOWN"
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30"):
                if metrics.get(key):
                    sev = metrics[key][0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                    break
            out.append({"cve_id": cid, "description": desc, "severity": sev})
        return out

    # ── one poll cycle (used by thread and by tests) ───────────
    def poll_once(self, targets, ntfy_topic=None, _injected_cves=None):
        """
        Run a single watch cycle. Returns list of new alerts raised.
        `_injected_cves` lets tests supply CVEs instead of hitting NVD.
        """
        fps = self._target_fingerprints(targets)
        recent = _injected_cves if _injected_cves is not None else self._fetch_recent_cves(hours=1)
        new_alerts = []
        for cve in recent:
            desc_tokens = _tokenize(cve.get("description", ""))
            for tgt, toks in fps.items():
                if not toks:
                    continue
                matched = toks & desc_tokens
                if matched:
                    tech = ", ".join(sorted(matched)[:4])
                    sent = self._notify(ntfy_topic, cve, tgt, tech)
                    self.db.add_sentinel_alert(cve["cve_id"], tgt, tech,
                                               severity=cve.get("severity", "UNKNOWN"),
                                               notification_sent=sent)
                    new_alerts.append({"cve_id": cve["cve_id"], "target": tgt,
                                       "matched_tech": tech, "severity": cve.get("severity")})
        SentinelMode._state["last_poll"] = datetime.now().isoformat()
        SentinelMode._state["polls"] += 1
        return new_alerts

    def _notify(self, topic, cve, target, tech):
        if not topic:
            return False
        msg = (f"New {cve.get('severity','')} {cve['cve_id']} affects {tech} on {target}. "
               f"NullShadow flagged possible exposure — verify and remediate.")
        try:
            r = requests.post(f"{NTFY_BASE}/{topic}", data=msg.encode("utf-8"),
                              headers={"Title": "NullShadow Sentinel Alert",
                                       "Priority": "high", "Tags": "warning,shield"},
                              timeout=10)
            return r.status_code == 200
        except Exception:
            return False

    # ── background thread control ──────────────────────────────
    def _loop(self, targets, interval, topic):
        while not SentinelMode._stop_event.is_set():
            try:
                self.poll_once(targets, ntfy_topic=topic)
            except Exception:
                pass
            # Sleep in small slices so stop() is responsive.
            waited = 0
            while waited < interval and not SentinelMode._stop_event.is_set():
                time.sleep(min(5, interval - waited))
                waited += 5

    def start(self, targets, interval=3600, ntfy_topic=None):
        if SentinelMode._state["running"]:
            return {"running": True, "note": "Sentinel already running."}
        if not ntfy_topic:
            ntfy_topic = "nullshadow-" + os.urandom(4).hex()
        SentinelMode._stop_event = threading.Event()
        SentinelMode._thread = threading.Thread(
            target=self._loop, args=(targets, interval, ntfy_topic), daemon=True)
        SentinelMode._thread.start()
        SentinelMode._state.update({"running": True, "targets": list(targets),
                                    "started_at": datetime.now().isoformat(),
                                    "topic": ntfy_topic, "polls": 0})
        return {"running": True, "topic": ntfy_topic, "targets": list(targets),
                "subscribe": f"Subscribe in the ntfy app to topic: {ntfy_topic}"}

    def stop(self):
        if SentinelMode._stop_event:
            SentinelMode._stop_event.set()
        SentinelMode._state["running"] = False
        return {"running": False}

    def status(self):
        st = dict(SentinelMode._state)
        st["recent_alerts"] = self.db.get_sentinel_alerts(limit=10)
        return st


def render_status(status, console):
    from rich.panel import Panel
    from rich.table import Table
    run = status["running"]
    console.print(Panel(
        f"[bold]Sentinel Mode:[/bold] {'[green]RUNNING[/green]' if run else '[red]STOPPED[/red]'}\n"
        f"Targets: {', '.join(status.get('targets') or []) or '—'}\n"
        f"ntfy topic: {status.get('topic') or '—'}\n"
        f"Polls: {status.get('polls', 0)}  ·  Last poll: {status.get('last_poll') or '—'}",
        border_style="green" if run else "red"))
    alerts = status.get("recent_alerts") or []
    if alerts:
        t = Table(title="Recent Sentinel alerts", header_style="bold red")
        t.add_column("CVE", style="cyan"); t.add_column("Target")
        t.add_column("Matched tech"); t.add_column("Severity"); t.add_column("Sent")
        for a in alerts:
            t.add_row(a["cve_id"], a["target"], a["matched_tech"],
                      a.get("severity", "?"), "✓" if a.get("notification_sent") else "—")
        console.print(t)


if __name__ == "__main__":
    from null_db.db import ScanDatabase
    db = ScanDatabase()
    sid = db.save_scan("watch.local", "Full Auto Recon", {})
    db.add_finding(target="watch.local", finding_type="open_port",
                   title="Port 443/tcp https — nginx 1.18.0", severity="INFO",
                   raw_data={"port": 443, "product": "nginx", "service": "https"}, scan_id=sid)
    sentinel = SentinelMode(db)
    # Inject a fake "just-published" CVE affecting nginx instead of calling NVD.
    injected = [{"cve_id": "CVE-2026-12345", "severity": "CRITICAL",
                 "description": "A flaw in nginx 1.18.0 allows remote code execution."}]
    alerts = sentinel.poll_once(["watch.local"], ntfy_topic=None, _injected_cves=injected)
    import json as _json
    print("alerts raised:", _json.dumps(alerts, indent=2))
    print("status polls:", sentinel.status()["polls"])
