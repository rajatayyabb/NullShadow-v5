"""
Phase K — Self-Healing Verification Loop.

Closes the loop on guided remediation: for each finding that had remediation
generated more than one monitoring interval ago, check (via scan_diff logic)
whether it is now resolved. If a finding persists after advice was given,
produce a DIFFERENT follow-up explaining why the fix may not have taken — do NOT
repeat the same advice verbatim. Effectiveness per remediation category is
tracked in remediation_stats, giving NullShadow one genuine learning signal.

Public API:
  record_remediation_given(db, finding) -> category
  verify_remediation_effectiveness(db, target) -> {checked, resolved, still_open:[...], stats}
  render_effectiveness(result, console)
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from datetime import datetime

# Why a fix might not have taken — follow-up guidance (not the original advice).
_PERSIST_REASONS = {
    "ssl_audit": "Weak TLS often persists because the service was not restarted after the config change, "
                 "a load-balancer/CDN terminates TLS separately, or an old virtual host still answers. "
                 "Verify which host actually serves the cipher and restart that service.",
    "http_header": "A missing header usually persists when the header was added at the app layer but a "
                   "reverse proxy/CDN strips or overrides it. Set it at the edge (proxy) as well.",
    "open_port": "An open port often persists because the firewall rule was applied to the wrong "
                 "interface/zone, or the service re-binds on restart. Confirm the rule is on the "
                 "internet-facing interface and the service is actually stopped.",
    "vulnerability": "A vulnerability can persist if the patch was staged but not deployed, the wrong "
                     "package version was installed, or multiple instances exist and only one was patched. "
                     "Re-check the running version on every host.",
    "_default": "The finding persists after remediation advice. Confirm the change was deployed to the "
                "live host (not staging), that the service was restarted, and that no proxy/CDN overrides it.",
}


def _category(finding):
    return (finding.get("finding_type") or "_default").lower()


def record_remediation_given(db, finding):
    """
    Mark that remediation advice was given for a finding, and bump the
    'given' counter for its category. Returns the category.
    """
    cat = _category(finding)
    fid = finding.get("id")
    rid = f"rem-{cat}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    if fid:
        db.mark_finding_remediated(fid, rid)
    db.upsert_remediation_stat(cat, given_delta=1)
    return cat


def _title_key(f):
    """A stable-ish identity for a finding across scans (type + title)."""
    return ((f.get("finding_type") or "").lower(), (f.get("title") or "").strip().lower())


def verify_remediation_effectiveness(db, target):
    """
    For findings that were given remediation in an earlier scan, check whether an
    equivalent finding still exists in the latest scan for the target.
    Resolved -> bump resolved counter. Still open -> produce a follow-up reason.
    """
    all_findings = db.get_findings(target=target)
    given = [f for f in all_findings if f.get("remediation_given_at")]
    if not given:
        return {"target": target, "checked": 0, "resolved": 0,
                "still_open": [], "stats": db.get_remediation_stats()}

    # Latest scan id for this target.
    scans = db.get_scans_for_target(target)
    latest_id = scans[0]["id"] if scans else None
    latest = db.get_findings(target=target, scan_id=latest_id) if latest_id else []
    latest_keys = {_title_key(f) for f in latest}

    resolved, still_open = 0, []
    for f in given:
        # Skip findings that ARE the latest-scan rows themselves.
        if f.get("scan_id") == latest_id:
            # It reappeared in the newest scan -> still open.
            cat = _category(f)
            db.upsert_remediation_stat(cat, resolved_delta=0)
            still_open.append({"id": f["id"], "title": f.get("title"),
                               "category": cat,
                               "followup": _PERSIST_REASONS.get(cat, _PERSIST_REASONS["_default"])})
            continue
        key = _title_key(f)
        if key in latest_keys:
            cat = _category(f)
            still_open.append({"id": f["id"], "title": f.get("title"),
                               "category": cat,
                               "followup": _PERSIST_REASONS.get(cat, _PERSIST_REASONS["_default"])})
        else:
            cat = _category(f)
            db.upsert_remediation_stat(cat, resolved_delta=1)
            resolved += 1

    return {"target": target, "checked": len(given), "resolved": resolved,
            "still_open": still_open, "stats": db.get_remediation_stats()}


def render_effectiveness(result, console):
    from rich.table import Table
    from rich.panel import Panel
    console.print(Panel(
        f"[bold]Remediation verification — {result['target']}[/bold]\n"
        f"Checked: {result['checked']}  ·  Resolved: [green]{result['resolved']}[/green]  "
        f"·  Still open: [red]{len(result['still_open'])}[/red]", border_style="cyan"))

    if result["still_open"]:
        console.print("\n[bold red]Findings that persist after remediation advice:[/bold red]")
        for s in result["still_open"]:
            console.print(f"  • [{s['category']}] {s['title']}")
            console.print(f"    ↳ {s['followup']}")

    stats = result.get("stats") or []
    if stats:
        t = Table(title="Remediation effectiveness by category", header_style="bold magenta")
        t.add_column("Category"); t.add_column("Given", justify="right")
        t.add_column("Resolved", justify="right"); t.add_column("Effectiveness", justify="right")
        for s in stats:
            eff = s.get("effectiveness", 0.0)
            color = "green" if eff >= 0.6 else "yellow" if eff >= 0.3 else "red"
            t.add_row(s["category"], str(s.get("given_count", 0)),
                      str(s.get("resolved_count", 0)),
                      f"[{color}]{round(eff*100)}%[/{color}]")
        console.print(t)


if __name__ == "__main__":
    from null_db.db import ScanDatabase
    db = ScanDatabase()
    # Scan 1: a weak-TLS finding, remediation given.
    s1 = db.save_scan("heal.local", "Monitor", {})
    fid = db.add_finding(target="heal.local", finding_type="ssl_audit",
                         title="Weak TLS version (TLSv1.0)", severity="MEDIUM",
                         raw_data={}, scan_id=s1)
    record_remediation_given(db, {"id": fid, "finding_type": "ssl_audit",
                                  "title": "Weak TLS version (TLSv1.0)"})
    # Scan 2 (latest): the weak-TLS finding is GONE -> should count as resolved.
    s2 = db.save_scan("heal.local", "Monitor", {})
    db.add_finding(target="heal.local", finding_type="open_port",
                   title="Port 443/tcp https", severity="INFO",
                   raw_data={"port": 443}, scan_id=s2)
    res = verify_remediation_effectiveness(db, "heal.local")
    import json as _json
    print(_json.dumps({k: v for k, v in res.items() if k != "stats"}, indent=2))
    print("stats:", _json.dumps(res["stats"], indent=2))
