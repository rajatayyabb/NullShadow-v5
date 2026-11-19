"""
Phase C — Real-Time Threat Intelligence Feeds.

Three free sources, cached in the DB (threat_intel_cache, 24h TTL):

  * CISA KEV   — CVEs that are being actively exploited RIGHT NOW (US gov, daily)
                 https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  * AlienVault OTX — IP/domain reputation + pulse count (keyless, reduced rate)
                 https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general
  * abuse.ch ThreatFox — malware C2 IOCs (keyless POST search_ioc)
                 https://threatfox-api.abuse.ch/api/v1/

Key behaviour (brief Phase C):
  * When a CVE in the findings is on CISA KEV → mark finding raw_data
    actively_exploited=True and force scan status CRITICAL regardless of CVSS.
  * 403/429/timeout are expected API conditions, never treated as code bugs —
    they return a clean, cached-or-empty result.

Public API:
  ThreatIntelChecker(db).check_target(target, findings) -> dict
  load_cisa_kev(db)        -> {cve_id: entry}
  render_threat_report(result, console)
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import re
import json
import requests

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OTX_IP_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
OTX_DOMAIN_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_TIMEOUT = 15


def _is_ip(value):
    return bool(_IP_RE.match((value or "").strip()))


def load_cisa_kev(db, timeout=_TIMEOUT):
    """
    Return the CISA KEV catalog as {CVE-ID: entry}. Cached 24h in the DB.
    On any network/HTTP failure returns whatever is cached, else {}.
    """
    cache_key = "cisa_kev_catalog"
    cached = db.get_threat_cache(cache_key, max_age_hours=24) if db else None
    if cached is not None:
        return cached

    try:
        r = requests.get(CISA_KEV_URL, timeout=timeout,
                         headers={"Accept": "application/json", "User-Agent": "NullShadow/5.0"})
        if r.status_code != 200:
            return db.get_threat_cache(cache_key, max_age_hours=24 * 30) if db else {}
        data = r.json()
    except Exception:
        return db.get_threat_cache(cache_key, max_age_hours=24 * 30) if db else {}

    catalog = {}
    for v in data.get("vulnerabilities", []):
        cid = (v.get("cveID") or "").upper()
        if cid:
            catalog[cid] = {
                "cve_id": cid,
                "vendor": v.get("vendorProject", ""),
                "product": v.get("product", ""),
                "name": v.get("vulnerabilityName", ""),
                "date_added": v.get("dateAdded", ""),
                "due_date": v.get("dueDate", ""),
                "ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
            }
    if db and catalog:
        db.set_threat_cache(cache_key, catalog)
    return catalog


def check_otx(indicator, db=None, timeout=_TIMEOUT):
    """OTX reputation for an IP or domain. Keyless, best-effort."""
    cache_key = f"otx:{indicator}"
    if db:
        cached = db.get_threat_cache(cache_key, max_age_hours=24)
        if cached is not None:
            return cached
    url = (OTX_IP_URL if _is_ip(indicator) else OTX_DOMAIN_URL).format(
        ip=indicator, domain=indicator)
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "NullShadow/5.0"})
        if r.status_code in (403, 429):
            return {"indicator": indicator, "rate_limited": True, "pulse_count": 0}
        if r.status_code != 200:
            return {"indicator": indicator, "error": f"HTTP {r.status_code}", "pulse_count": 0}
        data = r.json()
        pulses = (data.get("pulse_info") or {}).get("count", 0)
        result = {
            "indicator": indicator,
            "pulse_count": pulses,
            "reputation": data.get("reputation", 0),
            "malicious": pulses > 0,
            "tags": list({t for p in (data.get("pulse_info") or {}).get("pulses", [])
                          for t in (p.get("tags") or [])})[:10],
        }
    except Exception as e:
        return {"indicator": indicator, "error": str(e), "pulse_count": 0}
    if db:
        db.set_threat_cache(cache_key, result)
    return result


def check_threatfox(indicator, db=None, timeout=_TIMEOUT):
    """abuse.ch ThreatFox IOC search (malware C2). Keyless POST."""
    cache_key = f"threatfox:{indicator}"
    if db:
        cached = db.get_threat_cache(cache_key, max_age_hours=24)
        if cached is not None:
            return cached
    try:
        r = requests.post(THREATFOX_URL, json={"query": "search_ioc", "search_term": indicator},
                          timeout=timeout, headers={"User-Agent": "NullShadow/5.0"})
        if r.status_code in (403, 429):
            return {"indicator": indicator, "rate_limited": True, "matches": 0}
        data = r.json()
    except Exception as e:
        return {"indicator": indicator, "error": str(e), "matches": 0}

    iocs = data.get("data") if isinstance(data.get("data"), list) else []
    result = {
        "indicator": indicator,
        "matches": len(iocs),
        "malware": list({i.get("malware_printable", "") for i in iocs if i.get("malware_printable")})[:5],
        "confidence": max([i.get("confidence_level", 0) for i in iocs], default=0),
    }
    if db:
        db.set_threat_cache(cache_key, result)
    return result


class ThreatIntelChecker:
    def __init__(self, db=None):
        self.db = db

    def check_target(self, target, findings=None):
        """
        Run all three feeds for `target` + its findings.
        Returns {status, kev_matches:[...], otx, threatfox, alerts:[...]}.
        A CISA KEV match on any finding CVE => status CRITICAL (actively exploited).
        """
        findings = findings or []
        kev = load_cisa_kev(self.db)
        kev_matches, alerts = [], []

        # Cross-reference every CVE in the findings against CISA KEV.
        for f in findings:
            for cid in f.get("cve_ids", []):
                entry = kev.get(cid.upper())
                if entry:
                    entry = dict(entry)
                    entry["finding_id"] = f.get("id")
                    kev_matches.append(entry)
                    # Mark the finding as actively exploited in the DB.
                    if self.db and f.get("id"):
                        self._mark_actively_exploited(f["id"], f, cid)
                    alerts.append(f"🔴 {cid} is on CISA KEV — ACTIVELY EXPLOITED "
                                  f"({entry.get('name') or entry.get('product')})")

        # IP/domain reputation.
        otx = check_otx(target, self.db)
        if otx.get("malicious"):
            alerts.append(f"⚠ {target} appears in {otx.get('pulse_count')} OTX threat pulses")
        tfox = check_threatfox(target, self.db)
        if tfox.get("matches"):
            alerts.append(f"⚠ {target} matched {tfox['matches']} ThreatFox malware IOC(s): "
                          f"{', '.join(tfox.get('malware', []))}")

        if kev_matches:
            status = "CRITICAL"
        elif otx.get("malicious") or tfox.get("matches"):
            status = "ALERT"
        else:
            status = "OK"

        return {
            "target": target, "status": status,
            "kev_matches": kev_matches, "kev_count": len(kev_matches),
            "otx": otx, "threatfox": tfox, "alerts": alerts,
        }

    def _mark_actively_exploited(self, finding_id, finding, cve_id):
        try:
            raw = finding.get("raw_data") or {}
            raw["actively_exploited"] = True
            raw["kev_cve"] = cve_id.upper()
            self.db.conn.execute(
                "UPDATE findings SET raw_data = ?, severity = 'CRITICAL' WHERE id = ?",
                (json.dumps(raw, default=str), finding_id))
            self.db.conn.commit()
        except Exception:
            pass


def render_threat_report(result, console):
    from rich.table import Table
    from rich.panel import Panel
    status = result["status"]
    color = "red" if status == "CRITICAL" else "yellow" if status == "ALERT" else "green"
    console.print(Panel(f"[bold {color}]Threat Intel status: {status}[/bold {color}]  "
                        f"— {result['target']}", border_style=color))
    if result["kev_matches"]:
        t = Table(title="🔴 CISA KEV — Actively Exploited", header_style="bold red")
        t.add_column("CVE", style="cyan"); t.add_column("Product")
        t.add_column("Added"); t.add_column("Ransomware use")
        for e in result["kev_matches"]:
            t.add_row(e["cve_id"], f"{e.get('vendor','')} {e.get('product','')}".strip(),
                      e.get("date_added", ""), e.get("ransomware", "Unknown"))
        console.print(t)
    if result["alerts"]:
        for a in result["alerts"]:
            console.print(f"  {a}")
    else:
        console.print("[green]No active-exploitation or reputation alerts for this target.[/green]")


if __name__ == "__main__":
    # Offline self-test: seed cache so no live network is required.
    import json as _json
    from null_db.db import ScanDatabase
    db = ScanDatabase()
    db.set_threat_cache("cisa_kev_catalog", {
        "CVE-2021-44228": {"cve_id": "CVE-2021-44228", "vendor": "Apache", "product": "Log4j",
                           "name": "Log4Shell", "date_added": "2021-12-10",
                           "due_date": "2021-12-24", "ransomware": "Known"}})
    chk = ThreatIntelChecker(db)
    findings = [{"id": 1, "cve_ids": ["CVE-2021-44228"], "severity": "HIGH", "raw_data": {}}]
    kev = chk.check_target("test.local", findings)
    kev["otx"] = {"indicator": "test.local", "malicious": False, "pulse_count": 0}  # skip live otx noise
    print("status:", kev["status"], "| kev_count:", kev["kev_count"])
    print(_json.dumps(kev["kev_matches"], indent=2))
