"""
Phase J — Compliance Mapper.

Attaches compliance-control references to findings and summarizes coverage per
framework (ISO27001, NIST_CSF, PCI_DSS, OWASP) using data/framework_controls.json.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import json

_DATA_FILE = os.path.join(os.path.dirname(__file__), "data", "framework_controls.json")
FRAMEWORKS = ["ISO27001", "NIST_CSF", "PCI_DSS", "OWASP"]


def _load():
    try:
        with open(_DATA_FILE, encoding="utf-8") as fh:
            return json.load(fh).get("frameworks", {})
    except Exception:
        return {}


def framework_name(framework):
    fw = _load().get(framework.upper())
    return fw.get("name", framework) if fw else framework


def controls_for(finding_type, framework):
    fw = _load().get(framework.upper())
    if not fw:
        return []
    return fw.get("controls", {}).get((finding_type or "").lower(), [])


def map_findings(findings, framework):
    """
    Attach a 'controls' list to each finding for the given framework.
    Returns (mapped_findings, coverage) where coverage maps control -> [finding ids].
    """
    framework = framework.upper()
    mapped = []
    coverage = {}
    for f in findings or []:
        ctrls = controls_for(f.get("finding_type"), framework)
        g = dict(f)
        g["controls"] = ctrls
        mapped.append(g)
        for c in ctrls:
            coverage.setdefault(c, []).append(f.get("id") or f.get("title"))
    # Continuous-monitoring control is always evidenced when scans exist.
    mon = _load().get(framework, {}).get("controls", {}).get("_monitoring", [])
    for c in mon:
        coverage.setdefault(c, [])
    return mapped, coverage


def summarize(findings, framework):
    mapped, coverage = map_findings(findings, framework)
    controls_hit = [c for c, ids in coverage.items() if ids]
    return {
        "framework": framework.upper(),
        "framework_name": framework_name(framework),
        "total_findings": len(findings or []),
        "controls_evidenced": len(controls_hit),
        "controls": sorted(coverage.keys()),
        "coverage": coverage,
        "mapped": mapped,
    }


if __name__ == "__main__":
    sample = [
        {"id": 1, "finding_type": "vulnerability", "title": "Log4Shell", "severity": "CRITICAL"},
        {"id": 2, "finding_type": "ssl_audit", "title": "Weak TLS", "severity": "MEDIUM"},
        {"id": 3, "finding_type": "sqli", "title": "SQLi in id param", "severity": "HIGH"},
    ]
    for fw in FRAMEWORKS:
        s = summarize(sample, fw)
        print(f"{fw}: {s['controls_evidenced']} controls evidenced -> {s['controls'][:3]}...")
