"""
Phase G — Cognitive Attack Prediction Engine (original contribution).

Predicts the probability and timeframe that a CVE will be weaponized (added to
CISA KEV / exploited in the wild), for the specific target's detected tech stack.

The core idea — the "time-to-weaponization" signal:
  * NVD records when a CVE was PUBLISHED.
  * CISA KEV records when it started being ACTIVELY EXPLOITED.
  * The gap between the two, measured across the whole KEV catalog, follows
    measurable patterns by severity. We compute those medians from the live KEV
    data itself (no external service) and use them to project each open CVE.

Probability factors (weighted, 0-100):
  * CVSS score           0.40
  * public PoC in NVD    0.30   (references mentioning exploit/PoC/github)
  * vendor risk          0.20   (how often this vendor appears in KEV)
  * recency vs median    0.10   (how far into the historical window we are)

Tech-stack matching: only predict for CVEs whose affected product/vendor matches
the target's WhatWeb/service fingerprints, so output is relevant, not generic.

No execution, no exploit generation — pure statistical reasoning over NVD + KEV.

Public API:
  build_weaponization_model(db)                    -> {medians, vendor_counts}
  predict_exploitation(cve_id, target, db, model?) -> dict
  predict_all(target, db)                          -> [predictions...]
  render_predictions(result, console)
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import statistics
from datetime import datetime, date

# Historical fallback medians (days NVD-publish -> KEV-added), used when the live
# KEV catalog is unavailable. Derived from published KEV timing analyses.
_FALLBACK_MEDIANS = {"CRITICAL": 15, "HIGH": 30, "MEDIUM": 90, "LOW": 180, "UNKNOWN": 60}


def _parse_date(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value)[:19]).date()
    except Exception:
        try:
            return datetime.strptime(str(value)[:10], "%Y-%m-%d").date()
        except Exception:
            return None


def build_weaponization_model(db):
    """
    Compute median days-to-weaponization per severity + vendor frequency from the
    live CISA KEV catalog (cross-referenced with cached NVD publish dates).
    Falls back to _FALLBACK_MEDIANS when there is not enough data.
    """
    from modules.intel.threat_feeds import load_cisa_kev
    kev = load_cisa_kev(db)
    gaps_by_sev = {}
    vendor_counts = {}

    for cid, entry in (kev or {}).items():
        vendor = (entry.get("vendor") or "").lower()
        if vendor:
            vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1
        added = _parse_date(entry.get("date_added"))
        cached = db.get_cached_cve(cid) if db else None
        published = _parse_date(cached.get("published")) if cached else None
        sev = (cached.get("severity") if cached else None) or "UNKNOWN"
        if added and published:
            gap = (added - published).days
            if gap >= 0:
                gaps_by_sev.setdefault(sev.upper(), []).append(gap)

    medians = {}
    for sev, fallback in _FALLBACK_MEDIANS.items():
        vals = gaps_by_sev.get(sev, [])
        medians[sev] = int(statistics.median(vals)) if len(vals) >= 5 else fallback

    total = sum(vendor_counts.values()) or 1
    return {"medians": medians, "vendor_counts": vendor_counts,
            "vendor_total": total, "kev_size": len(kev or {})}


def _has_public_poc(cve_data):
    if not cve_data:
        return False
    refs = " ".join(cve_data.get("references", []) or []).lower()
    return any(k in refs for k in ("exploit-db", "github.com", "/poc", "exploit", "metasploit"))


def _tech_matches(cve_data, tech_terms):
    """True if the CVE description mentions any detected tech term."""
    if not tech_terms:
        return True  # no fingerprint -> don't filter
    desc = (cve_data.get("description", "") if cve_data else "").lower()
    return any(t.lower() in desc for t in tech_terms if len(t) >= 3)


_TECH_STOPWORDS = {"the", "and", "for", "server", "service", "http", "https",
                   "tcp", "udp", "port", "open", "version", "software"}


def _tokenize_tech(value):
    """Split a product string into significant lowercase word tokens (len>=3)."""
    import re as _re
    out = set()
    for tok in _re.split(r"[^A-Za-z0-9.]+", str(value).lower()):
        tok = tok.strip(".")
        if len(tok) >= 3 and tok not in _TECH_STOPWORDS and not tok.replace(".", "").isdigit():
            out.add(tok)
    return out


def _target_tech_terms(db, target):
    """Collect tech/product terms from the target's findings (WhatWeb / open ports)."""
    terms = set()
    for f in db.get_findings(target=target):
        raw = f.get("raw_data") or {}
        for key in ("product", "service", "name", "server", "cms", "framework"):
            v = raw.get(key)
            if v and isinstance(v, str):
                terms |= _tokenize_tech(v)
        # WhatWeb-style tech list
        for t in (raw.get("technologies") or []):
            if isinstance(t, str):
                terms |= _tokenize_tech(t)
        # Also mine significant words from the finding title.
        terms |= _tokenize_tech(f.get("title", ""))
    return {t for t in terms if t}


def predict_exploitation(cve_id, target, db, model=None):
    """
    Predict weaponization probability + timeframe for one CVE on one target.
    Returns a dict (status 'ok' or 'skipped').
    """
    cve_id = (cve_id or "").upper().strip()
    model = model or build_weaponization_model(db)
    cached = db.get_cached_cve(cve_id) if db else None

    # Already weaponized?
    from modules.intel.threat_feeds import load_cisa_kev
    kev = load_cisa_kev(db)
    if cve_id in (kev or {}):
        return {"cve_id": cve_id, "status": "already_exploited",
                "probability": 100, "days_until_weaponized": 0,
                "note": "Already on CISA KEV — exploited in the wild now."}

    cvss = None
    sev = "UNKNOWN"
    if cached:
        cvss = cached.get("cvss_score")
        sev = (cached.get("severity") or "UNKNOWN").upper()

    try:
        cvss = float(cvss) if cvss is not None else None
    except (TypeError, ValueError):
        cvss = None

    # Factor 1: CVSS (0-1)
    f_cvss = (cvss / 10.0) if cvss is not None else 0.5
    # Factor 2: public PoC
    f_poc = 1.0 if _has_public_poc(cached) else 0.0
    # Factor 3: vendor risk — how often this vendor shows up in KEV
    vendor_term = None
    if cached:
        desc = (cached.get("description") or "").lower()
        for v in model["vendor_counts"]:
            if v in desc:
                vendor_term = v
                break
    f_vendor = 0.0
    if vendor_term:
        # normalise against the most frequent vendor
        top = max(model["vendor_counts"].values()) if model["vendor_counts"] else 1
        f_vendor = model["vendor_counts"].get(vendor_term, 0) / top

    # Factor 4: recency vs median window
    published = _parse_date(cached.get("published")) if cached else None
    median = model["medians"].get(sev, _FALLBACK_MEDIANS["UNKNOWN"])
    days_since_publish = (date.today() - published).days if published else 0
    # the deeper we are into the historical window, the more "due" it is
    f_recency = min(1.0, days_since_publish / median) if median else 0.5

    probability = round(100 * (0.40 * f_cvss + 0.30 * f_poc +
                               0.20 * f_vendor + 0.10 * f_recency))
    probability = max(0, min(100, probability))

    days_until = max(0, median - days_since_publish)

    return {
        "cve_id": cve_id,
        "status": "ok",
        "severity": sev,
        "cvss": cvss,
        "probability": probability,
        "days_until_weaponized": days_until,
        "median_window_days": median,
        "days_since_publish": days_since_publish,
        "exposure_days": days_since_publish,
        "has_public_poc": bool(f_poc),
        "vendor": vendor_term,
        "factors": {"cvss": round(f_cvss, 2), "poc": f_poc,
                    "vendor": round(f_vendor, 2), "recency": round(f_recency, 2)},
    }


def predict_all(target, db):
    """Predict for every distinct, tech-relevant CVE in the target's findings."""
    model = build_weaponization_model(db)
    tech_terms = _target_tech_terms(db, target)
    seen, preds = set(), []
    for f in db.get_findings(target=target):
        for cid in f.get("cve_ids", []):
            cu = cid.upper()
            if cu in seen:
                continue
            seen.add(cu)
            cached = db.get_cached_cve(cu) if db else None
            if not _tech_matches(cached, tech_terms):
                continue
            p = predict_exploitation(cu, target, db, model=model)
            if p.get("status") in ("ok", "already_exploited"):
                preds.append(p)
    preds.sort(key=lambda p: (p["probability"], -p.get("days_until_weaponized", 999)),
               reverse=True)
    return {"target": target, "model_kev_size": model["kev_size"],
            "tech_terms": sorted(tech_terms), "predictions": preds}


def render_predictions(result, console):
    from rich.table import Table
    preds = result.get("predictions", [])
    if not preds:
        console.print("[yellow]No CVEs to predict for this target (run a vuln scan "
                      "so findings have CVE ids + are tech-matched).[/yellow]")
        return
    t = Table(title=f"🧠 Cognitive Attack Prediction — {result['target']}",
              header_style="bold magenta")
    t.add_column("CVE", style="cyan"); t.add_column("Prob.", justify="right")
    t.add_column("Weaponized in", justify="right"); t.add_column("Exposure", justify="right")
    t.add_column("PoC"); t.add_column("Severity")
    for p in preds:
        days = p.get("days_until_weaponized", 0)
        color = "red" if days <= 7 else "yellow" if days <= 14 else "green"
        prob_color = "red" if p["probability"] >= 70 else "yellow" if p["probability"] >= 40 else "white"
        t.add_row(p["cve_id"], f"[{prob_color}]{p['probability']}%[/{prob_color}]",
                  f"[{color}]{days}d[/{color}]" if p["status"] == "ok" else "[red]NOW[/red]",
                  f"{p.get('exposure_days', 0)}d",
                  "✓" if p.get("has_public_poc") else "—", p.get("severity", "?"))
    console.print(t)
    top = preds[0]
    if top["status"] == "ok":
        console.print(f"\n[bold]{top['probability']}% probability {top['cve_id']} will be "
                      f"weaponized within ~{top['days_until_weaponized']} days. "
                      f"Your exposure window: {top.get('exposure_days',0)} days old.[/bold]")


if __name__ == "__main__":
    import json as _json
    from null_db.db import ScanDatabase
    db = ScanDatabase()
    # Seed KEV medians source + a non-KEV CVE with a PoC to predict.
    db.set_threat_cache("cisa_kev_catalog", {
        "CVE-2021-44228": {"cve_id": "CVE-2021-44228", "vendor": "Apache", "product": "Log4j",
                           "date_added": "2021-12-10"}})
    db.cache_cve("CVE-2021-44228", {"severity": "CRITICAL", "published": "2021-12-09",
                                    "references": []})
    db.cache_cve("CVE-2026-9999", {"severity": "HIGH", "cvss_score": 8.1,
                                   "published": "2026-10-20", "description": "apache http server rce",
                                   "references": ["https://github.com/x/poc"]})
    sid = db.save_scan("predict.local", "Vuln Scan", {})
    db.add_finding(target="predict.local", finding_type="vulnerability", title="apache rce",
                   severity="HIGH", cve_ids=["CVE-2026-9999"],
                   raw_data={"product": "Apache httpd"}, scan_id=sid)
    res = predict_all("predict.local", db)
    print(_json.dumps(res["predictions"], indent=2))
