"""
Phase H — Security DNA: Breach Pattern Matching (original contribution).

Builds a "security DNA" fingerprint for a target from the data NullShadow already
collects (open ports, tech stack, SSL config, missing security headers, CVE type
pattern) and compares it against curated fingerprints of organizations that were
breached in well-documented public campaigns (data/breach_patterns.json).

Output: "Your profile matches 78% similarity to the pre-breach fingerprint of
organizations affected by the 2023 MOVEit campaign. Key matching factors: ..."

No execution, no target interaction — pure analysis over existing findings.

Public API:
  build_security_dna(db, target)                 -> dna dict
  calculate_dna_similarity(dna, pattern)         -> {score, factors}
  match_breach_patterns(db, target, top_n=3)     -> {target, dna, matches:[...]}
  render_dna(result, console)
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import json
import re

_DATA_FILE = os.path.join(os.path.dirname(__file__), "data", "breach_patterns.json")

# Headers we expect a well-configured site to set; absence is a DNA marker.
_EXPECTED_HEADERS = ["Content-Security-Policy", "X-Frame-Options",
                     "Strict-Transport-Security", "X-Content-Type-Options"]

_CVE_TYPE_KEYWORDS = {
    "rce": ["remote code", "rce", "code execution", "arbitrary code"],
    "sql injection": ["sql injection", "sqli"],
    "xss": ["cross-site scripting", "xss"],
    "ssrf": ["server-side request", "ssrf"],
    "deserialization": ["deserializ", "serialized object"],
    "authentication bypass": ["authentication bypass", "auth bypass", "improper authentication"],
    "information disclosure": ["information disclosure", "info leak", "memory disclosure"],
    "file upload": ["file upload", "unrestricted upload"],
    "file transfer": ["file transfer"],
    "session hijack": ["session", "token leak"],
}


def _load_patterns():
    try:
        with open(_DATA_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh).get("patterns", [])
    except Exception:
        return []


def _tokenize(value):
    out = set()
    for tok in re.split(r"[^a-z0-9.]+", str(value).lower()):
        if len(tok) >= 3:
            out.add(tok)
    return out


def build_security_dna(db, target):
    """Extract a structured fingerprint from the target's stored findings."""
    findings = db.get_findings(target=target)
    tech, ports, cve_types = set(), set(), set()
    missing_headers = set()
    ssl_weak = False
    cve_ids = set()

    for f in findings:
        raw = f.get("raw_data") or {}
        ftype = (f.get("finding_type") or "").lower()
        title = (f.get("title") or "")
        desc = (f.get("description") or "")

        # Ports
        port = raw.get("port")
        if port:
            try:
                ports.add(int(port))
            except (TypeError, ValueError):
                pass

        # Tech stack from product/service/tech + title words
        for key in ("product", "service", "name", "server", "cms", "framework"):
            if raw.get(key):
                tech |= _tokenize(raw[key])
        for t in (raw.get("technologies") or []):
            tech |= _tokenize(t)
        if ftype == "open_port":
            tech |= _tokenize(title)

        # SSL weakness
        if ftype == "ssl_audit" or "tls" in title.lower() or "ssl" in title.lower():
            blob = (title + " " + desc + " " + str(raw)).lower()
            if any(w in blob for w in ("weak", "tlsv1.0", "tlsv1.1", "sslv", "rc4", "legacy")):
                ssl_weak = True

        # Missing security headers (from HTTP header analyzer findings)
        if "header" in ftype or "header" in title.lower():
            blob = (title + " " + desc + " " + json.dumps(raw, default=str)).lower()
            for h in _EXPECTED_HEADERS:
                if h.lower() in blob and ("missing" in blob or "absent" in blob or "not set" in blob):
                    missing_headers.add(h)

        # CVE type pattern (from CVE descriptions in cache)
        for cid in f.get("cve_ids", []):
            cve_ids.add(cid.upper())
            cached = db.get_cached_cve(cid) if db else None
            cdesc = (cached.get("description", "") if cached else (title + " " + desc)).lower()
            for ctype, kws in _CVE_TYPE_KEYWORDS.items():
                if any(k in cdesc for k in kws):
                    cve_types.add(ctype)

    # posture trend (optional context)
    posture_rows = db.get_posture_history(target)
    trend = None
    if len(posture_rows) >= 2:
        trend = posture_rows[-1]["posture_score"] - posture_rows[0]["posture_score"]

    return {
        "target": target,
        "tech": sorted(tech),
        "ports": sorted(ports),
        "missing_headers": sorted(missing_headers),
        "cve_types": sorted(cve_types),
        "ssl_weak": ssl_weak,
        "cve_count": len(cve_ids),
        "posture_trend": trend,
    }


def _overlap(a, b):
    a, b = set(a), set(b)
    if not b:
        return 0.0, []
    matched = a & b
    return (len(matched) / len(b)), sorted(matched)


def _tech_overlap(dna_tech, pattern_tech):
    """Lenient tech overlap: a pattern tech matches if it's a token in the DNA."""
    dna = set(dna_tech)
    matched = [p for p in pattern_tech if any(p in d or d in p for d in dna)]
    frac = len(matched) / len(pattern_tech) if pattern_tech else 0.0
    return frac, matched


def calculate_dna_similarity(dna, pattern):
    """Weighted overlap score (0-100) between a target DNA and a breach pattern."""
    ind = pattern.get("indicators", {})
    w = pattern.get("weights", {"tech": 0.4, "ports": 0.2, "missing_headers": 0.2, "cve_types": 0.2})

    tech_frac, tech_m = _tech_overlap(dna["tech"], ind.get("tech", []))
    port_frac, port_m = _overlap(dna["ports"], ind.get("ports", []))
    hdr_frac, hdr_m = _overlap(dna["missing_headers"], ind.get("missing_headers", []))
    cve_frac, cve_m = _overlap(dna["cve_types"], ind.get("cve_types", []))

    score = 100 * (w.get("tech", 0) * tech_frac +
                   w.get("ports", 0) * port_frac +
                   w.get("missing_headers", 0) * hdr_frac +
                   w.get("cve_types", 0) * cve_frac)

    # SSL-weak alignment nudges the score slightly.
    if ind.get("ssl_weak") and dna.get("ssl_weak"):
        score = min(100, score + 5)

    factors = []
    if tech_m:
        factors.append("tech: " + ", ".join(tech_m[:5]))
    if port_m:
        factors.append("ports: " + ", ".join(str(p) for p in port_m))
    if hdr_m:
        factors.append("missing headers: " + ", ".join(hdr_m))
    if cve_m:
        factors.append("CVE types: " + ", ".join(cve_m))
    if ind.get("ssl_weak") and dna.get("ssl_weak"):
        factors.append("weak TLS/SSL")

    return {"score": round(score), "factors": factors,
            "matched": {"tech": tech_m, "ports": port_m,
                        "missing_headers": hdr_m, "cve_types": cve_m}}


def match_breach_patterns(db, target, top_n=3):
    dna = build_security_dna(db, target)
    patterns = _load_patterns()
    matches = []
    for p in patterns:
        sim = calculate_dna_similarity(dna, p)
        matches.append({
            "id": p["id"], "name": p["name"], "year": p.get("year"),
            "summary": p.get("summary", ""),
            "similarity": sim["score"], "factors": sim["factors"],
        })
    matches.sort(key=lambda m: m["similarity"], reverse=True)
    return {"target": target, "dna": dna, "matches": matches[:top_n]}


def render_dna(result, console):
    from rich.table import Table
    from rich.panel import Panel
    dna = result["dna"]
    console.print(Panel(
        f"[bold]Security DNA — {result['target']}[/bold]\n"
        f"Tech: {', '.join(dna['tech'][:12]) or '—'}\n"
        f"Ports: {', '.join(str(p) for p in dna['ports']) or '—'}\n"
        f"Missing headers: {', '.join(dna['missing_headers']) or '—'}\n"
        f"CVE types: {', '.join(dna['cve_types']) or '—'}\n"
        f"Weak TLS/SSL: {dna['ssl_weak']}", border_style="cyan"))

    t = Table(title="🧬 Breach-pattern similarity", header_style="bold red")
    t.add_column("Breach pattern", style="cyan"); t.add_column("Year")
    t.add_column("Similarity", justify="right"); t.add_column("Matching factors", style="white")
    for m in result["matches"]:
        s = m["similarity"]
        color = "red" if s >= 60 else "yellow" if s >= 35 else "green"
        t.add_row(m["name"], str(m.get("year", "")),
                  f"[{color}]{s}%[/{color}]", "; ".join(m["factors"]) or "—")
    console.print(t)
    top = result["matches"][0] if result["matches"] else None
    if top and top["similarity"] >= 35:
        console.print(Panel(
            f"[bold yellow]WARNING:[/bold yellow] profile matches [red]{top['similarity']}%[/red] "
            f"to the pre-breach fingerprint of [bold]{top['name']}[/bold].\n"
            f"Key matching factors: {'; '.join(top['factors'])}.",
            border_style="red"))


if __name__ == "__main__":
    from null_db.db import ScanDatabase
    db = ScanDatabase()
    sid = db.save_scan("dna.local", "Full Auto Recon", {})
    db.add_finding(target="dna.local", finding_type="open_port", title="Port 443/tcp https — Apache httpd 2.4",
                   severity="INFO", raw_data={"port": 443, "product": "Apache httpd", "service": "https"}, scan_id=sid)
    db.add_finding(target="dna.local", finding_type="open_port", title="Port 3306/tcp mysql",
                   severity="INFO", raw_data={"port": 3306, "service": "mysql"}, scan_id=sid)
    db.add_finding(target="dna.local", finding_type="http_header", title="Missing security header: X-Frame-Options",
                   description="X-Frame-Options header is missing / not set", severity="LOW",
                   raw_data={}, scan_id=sid)
    db.add_finding(target="dna.local", finding_type="ssl_audit", title="Weak TLS version (TLSv1.0)",
                   severity="MEDIUM", raw_data={}, scan_id=sid)
    db.cache_cve("CVE-2021-0001", {"severity": "HIGH", "description": "sql injection in wordpress plugin"})
    db.add_finding(target="dna.local", finding_type="vulnerability", title="wordpress sqli",
                   severity="HIGH", cve_ids=["CVE-2021-0001"], raw_data={"product": "wordpress"}, scan_id=sid)
    res = match_breach_patterns(db, "dna.local")
    import json as _json
    print(_json.dumps(res["matches"], indent=2))
