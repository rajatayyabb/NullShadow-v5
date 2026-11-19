"""
Phase F — AI Attack Narrative (Purple Team Mode).

Generates a written narrative describing how an attacker would chain the
discovered findings into a realistic breach scenario, plus one Priority Action.
Pure reasoning over existing data — NO exploit code, NO payloads, NO target
interaction. The AI prompt is explicitly constrained; a deterministic rule-based
fallback is used when no AI engine is available.

Public API:
  generate_attack_narrative(findings, ai_engine=None, target="") -> {narrative, priority_action, method}
  render_narrative(result, console)
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 3}

_SYSTEM_PROMPT = (
    "You are a defensive security analyst writing a PURPLE-TEAM attack-path "
    "analysis for a system the user is authorized to assess. Write attack-chain "
    "analysis and defensive prioritization ONLY. Do NOT include exploit code, "
    "payloads, specific attack commands, or step-by-step offensive instructions. "
    "Keep it under 400 words. End with exactly one line beginning 'Priority Action:' "
    "naming the single most important fix."
)


def _sort_findings(findings):
    return sorted(findings or [], key=lambda f: _SEV_ORDER.get(
        (f.get("severity") or "UNKNOWN").upper(), 3))


def _build_context(findings, target):
    lines = [f"Target: {target or 'unknown'}", f"Total findings: {len(findings)}", ""]
    for f in _sort_findings(findings)[:25]:
        cves = ", ".join(f.get("cve_ids", [])) or "—"
        lines.append(f"- [{(f.get('severity') or 'INFO').upper()}] "
                     f"{f.get('finding_type','')}: {f.get('title','')} (CVE: {cves})")
    return "\n".join(lines)


def _rule_based_narrative(findings, target):
    """Deterministic fallback narrative when no AI engine is available."""
    ranked = _sort_findings(findings)
    if not ranked:
        return {"narrative": "No findings available to build an attack path.",
                "priority_action": "Run a scan (vuln scan / Auto Full Recon) first.",
                "method": "rule"}

    entry = ranked[0]
    entry_sev = (entry.get("severity") or "INFO").upper()
    highs = [f for f in ranked if (f.get("severity") or "").upper() in ("CRITICAL", "HIGH")]
    cves = [c for f in ranked for c in f.get("cve_ids", [])]

    parts = []
    parts.append(
        f"Estimated attack path for {target or 'the target'}: an attacker would most "
        f"likely begin at the highest-value exposure — "
        f"\"{entry.get('title','')}\" ({entry_sev}) — as the initial entry point, "
        f"because it offers the greatest access for the least effort.")
    if len(highs) > 1:
        chain = " → ".join(f.get("title", "") for f in highs[:4])
        parts.append(
            f"From there, the remaining high-severity findings form a plausible chain "
            f"({chain}): each weakness lowers the cost of reaching the next, so "
            f"foothold could escalate toward sensitive data or lateral movement.")
    if cves:
        parts.append(
            f"Known CVEs in scope ({', '.join(sorted(set(cves))[:6])}) mean public "
            f"vulnerability information already exists, shortening an attacker's "
            f"research time. Treat any CVE on CISA KEV as an immediate priority.")
    parts.append(
        "Defensive reading: breaking the earliest link in this chain collapses the "
        "rest of the path, so remediation effort should be front-loaded on the entry point.")

    priority = (f"Remediate \"{entry.get('title','')}\" first — it is the lowest-cost "
                f"entry point and anchors the rest of the chain.")
    return {"narrative": "\n\n".join(parts), "priority_action": priority, "method": "rule"}


def generate_attack_narrative(findings, ai_engine=None, target=""):
    """
    Build a purple-team narrative. Uses the AI engine when available (with a
    constrained prompt), otherwise a deterministic rule-based narrative.
    """
    findings = findings or []
    if ai_engine is not None:
        try:
            context = _build_context(findings, target)
            prompt = (f"{_SYSTEM_PROMPT}\n\nFindings:\n{context}\n\n"
                      f"Write the attack-path analysis now.")
            text = None
            for method in ("analyze", "chat", "ask", "complete", "generate"):
                fn = getattr(ai_engine, method, None)
                if callable(fn):
                    text = fn(prompt)
                    break
            if text and str(text).strip():
                text = str(text).strip()
                # Split off the Priority Action line if present.
                priority = ""
                for line in text.splitlines():
                    if line.strip().lower().startswith("priority action"):
                        priority = line.split(":", 1)[-1].strip()
                        break
                if not priority:
                    priority = _rule_based_narrative(findings, target)["priority_action"]
                return {"narrative": text, "priority_action": priority, "method": "ai"}
        except Exception:
            pass  # fall through to rule-based
    return _rule_based_narrative(findings, target)


def render_narrative(result, console):
    from rich.panel import Panel
    console.print(Panel(result["narrative"],
                        title=f"🟣 Attack Narrative ({result['method']})",
                        border_style="magenta"))
    console.print(Panel(f"[bold]Priority Action:[/bold] {result['priority_action']}",
                        border_style="red"))


if __name__ == "__main__":
    sample = [
        {"severity": "CRITICAL", "finding_type": "vulnerability",
         "title": "Log4Shell RCE on port 8080", "cve_ids": ["CVE-2021-44228"]},
        {"severity": "HIGH", "finding_type": "vulnerability",
         "title": "Exposed phpMyAdmin login", "cve_ids": []},
        {"severity": "MEDIUM", "finding_type": "ssl_audit",
         "title": "Weak TLS version (TLSv1.0)", "cve_ids": []},
    ]
    res = generate_attack_narrative(sample, ai_engine=None, target="demo.local")
    print("METHOD:", res["method"])
    print(res["narrative"])
    print("\nPRIORITY:", res["priority_action"])
