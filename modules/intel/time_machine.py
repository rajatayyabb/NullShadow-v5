"""
Phase B — Security Posture Time Machine.

Calculates the exact number of days a target has been exposed to each CVE, by
combining two data points NullShadow already stores:

  * findings.created_at  — when the CVE was FIRST observed on the target
  * cve_cache.published   — when the CVE was published to NVD

    exposure_start = max(first_seen_scan_date, cve_publish_date)
    days_exposed   = (today - exposure_start).days

"You have been exposed to CVE-2024-XXXX for 47 days" is more actionable than
"CVE found today." No execution, no target interaction — pure analysis over the
existing findings + cve_cache tables.

Public API:
  calculate_exposure_window(db, target, cve_id) -> dict
  exposure_analysis(db, target)                 -> {target, exposures:[...], ...}
  get_time_machine_chart_data(db, target)       -> Chart.js-ready JSON
  render_exposure_table(result, console)        -> Rich table for the CLI (menu 42)
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from datetime import datetime, date


def _parse_date(value):
    """Parse an ISO date/datetime string into a date, or None."""
    if not value:
        return None
    s = str(value)[:19]
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s[:len(datetime.now().strftime(fmt))], fmt).date()
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(s).date()
    except Exception:
        return None


def _classify_exposure(severity, days):
    sev = (severity or "UNKNOWN").upper()
    high = sev in ("CRITICAL", "HIGH")
    if high and days is not None and days > 30:
        return "PROLONGED"
    if high and days is not None and days > 7:
        return "CRITICAL_EXPOSURE"
    if days is not None and days > 30:
        return "HIGH_EXPOSURE"
    return "NORMAL"


def _cve_publish_date(db, cve_id):
    """Publish date for a CVE from the local cve_cache (no live lookup here)."""
    try:
        cached = db.get_cached_cve(cve_id)
    except Exception:
        cached = None
    if cached and cached.get("published"):
        return _parse_date(cached["published"])
    return None


def _cve_severity(db, cve_id, fallback="UNKNOWN"):
    try:
        cached = db.get_cached_cve(cve_id)
    except Exception:
        cached = None
    if cached and cached.get("severity"):
        return cached["severity"]
    return fallback


def calculate_exposure_window(db, target, cve_id):
    """
    Return the exposure window for one CVE on one target:
      {cve_id, first_seen, publish_date, exposure_start, days_exposed, severity, class}
    days_exposed is None when we have no first-seen date at all.
    """
    cve_id = (cve_id or "").upper().strip()
    findings = [f for f in db.get_findings(target=target)
                if cve_id in [c.upper() for c in f.get("cve_ids", [])]]
    if not findings:
        return {"cve_id": cve_id, "days_exposed": None,
                "error": "CVE not found in findings for this target"}

    # Earliest time this CVE was observed on the target.
    first_seen = None
    sev = "UNKNOWN"
    for f in findings:
        d = _parse_date(f.get("created_at"))
        if d and (first_seen is None or d < first_seen):
            first_seen = d
        if (f.get("severity") or "").upper() not in ("", "INFO", "UNKNOWN"):
            sev = f["severity"]

    publish_date = _cve_publish_date(db, cve_id)
    sev = _cve_severity(db, cve_id, fallback=sev)

    # exposure_start = the later of (first observed) and (published).
    candidates = [d for d in (first_seen, publish_date) if d]
    exposure_start = max(candidates) if candidates else None
    days_exposed = (date.today() - exposure_start).days if exposure_start else None

    return {
        "cve_id": cve_id,
        "severity": (sev or "UNKNOWN").upper(),
        "first_seen": first_seen.isoformat() if first_seen else None,
        "publish_date": publish_date.isoformat() if publish_date else None,
        "exposure_start": exposure_start.isoformat() if exposure_start else None,
        "days_exposed": days_exposed,
        "class": _classify_exposure(sev, days_exposed),
    }


def exposure_analysis(db, target):
    """
    Run calculate_exposure_window for every distinct CVE in the target's findings,
    sorted by days_exposed descending (longest exposure first).
    """
    findings = db.get_findings(target=target)
    cve_ids = []
    seen = set()
    for f in findings:
        for c in f.get("cve_ids", []):
            cu = c.upper()
            if cu not in seen:
                seen.add(cu)
                cve_ids.append(cu)

    exposures = []
    for cid in cve_ids:
        w = calculate_exposure_window(db, target, cid)
        if w.get("days_exposed") is not None:
            exposures.append(w)

    exposures.sort(key=lambda e: e.get("days_exposed") or 0, reverse=True)
    worst = exposures[0] if exposures else None
    return {
        "target": target,
        "cve_count": len(cve_ids),
        "analyzed": len(exposures),
        "worst": worst,
        "exposures": exposures,
    }


def get_time_machine_chart_data(db, target):
    """
    Chart.js horizontal-bar timeline data: each CVE is a bar running from its
    exposure_start to today. Returns {labels, days, starts, classes, severities}.
    """
    res = exposure_analysis(db, target)
    labels, days, starts, classes, severities = [], [], [], [], []
    for e in res["exposures"]:
        labels.append(e["cve_id"])
        days.append(e["days_exposed"])
        starts.append(e["exposure_start"])
        classes.append(e["class"])
        severities.append(e["severity"])
    return {"target": target, "labels": labels, "days": days,
            "starts": starts, "classes": classes, "severities": severities}


def render_exposure_table(result, console):
    """Rich table for CLI menu [42]."""
    from rich.table import Table
    from rich.panel import Panel
    if not result.get("exposures"):
        console.print("[yellow]No CVE exposures with a known exposure window for this target. "
                      "Run a vuln scan / Auto Full Recon first so CVEs are enriched.[/yellow]")
        return
    t = Table(title=f"🕰  Security Posture Time Machine — {result['target']}",
              header_style="bold red")
    t.add_column("CVE", style="cyan")
    t.add_column("Severity")
    t.add_column("Exposure start", style="white")
    t.add_column("Days exposed", justify="right")
    t.add_column("Classification")
    for e in result["exposures"]:
        cls = e["class"]
        color = ("red" if cls in ("CRITICAL_EXPOSURE", "PROLONGED")
                 else "yellow" if cls == "HIGH_EXPOSURE" else "green")
        badge = f"[{color}]{cls}[/{color}]"
        sev = e["severity"]
        sev_color = "red" if sev in ("CRITICAL", "HIGH") else "yellow" if sev == "MEDIUM" else "white"
        t.add_row(e["cve_id"], f"[{sev_color}]{sev}[/{sev_color}]",
                  e["exposure_start"] or "—", str(e["days_exposed"]), badge)
    console.print(t)
    worst = result["worst"]
    if worst:
        console.print(Panel(
            f"[bold]You have been exposed to {worst['cve_id']} for "
            f"[red]{worst['days_exposed']} days[/red][/bold] "
            f"(since {worst['exposure_start']}).",
            border_style="red"))


if __name__ == "__main__":
    # Self-test against a throwaway in-memory-style DB seeded with a CVE.
    import tempfile, json
    os.environ.setdefault("NULLSHADOW_SELFTEST", "1")
    from null_db.db import ScanDatabase
    db = ScanDatabase()
    db.cache_cve("CVE-2024-0001", {"cve_id": "CVE-2024-0001", "severity": "CRITICAL",
                                   "cvss_score": 9.8, "published": "2024-01-01"})
    sid = db.save_scan("selftest.local", "Vuln Scan", {})
    db.add_finding(target="selftest.local", finding_type="vulnerability",
                   title="nginx RCE", severity="CRITICAL",
                   cve_ids=["CVE-2024-0001"], raw_data={"port": 443}, scan_id=sid)
    res = exposure_analysis(db, "selftest.local")
    print(json.dumps(res, indent=2))
