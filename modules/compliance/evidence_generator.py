"""
Phase J — Compliance Evidence Generator.

Builds an audit-ready PDF (ReportLab) from real NullShadow scan data, mapping
findings to a chosen framework's controls and documenting continuous monitoring.

generate_report(target, framework, db) -> path to the generated PDF.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle, PageBreak)

from modules.compliance.compliance_mapper import summarize, framework_name

RED = colors.HexColor("#cc0000")
DARK = colors.HexColor("#0d0d0d")


def _org_name():
    try:
        from config.config import ORG_NAME
        return ORG_NAME
    except Exception:
        return os.getenv("NULLSHADOW_ORG", "Your Organization")


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("NSTitle", parent=ss["Title"], textColor=RED, fontSize=22))
    ss.add(ParagraphStyle("NSH2", parent=ss["Heading2"], textColor=colors.HexColor("#333333")))
    ss.add(ParagraphStyle("NSBody", parent=ss["BodyText"], fontSize=9, leading=13))
    ss.add(ParagraphStyle("NSMeta", parent=ss["BodyText"], fontSize=8,
                          textColor=colors.HexColor("#666666")))
    return ss


def generate_report(target, framework, db, out_dir=None):
    framework = framework.upper()
    findings = db.get_findings(target=target)
    summary = summarize(findings, framework)
    scans = db.get_scans_for_target(target)

    out_dir = out_dir or os.path.join(os.path.dirname(__file__), "..", "..", "reports")
    os.makedirs(out_dir, exist_ok=True)
    safe_target = "".join(c if c.isalnum() else "_" for c in target)[:40]
    path = os.path.join(out_dir, f"compliance_{framework}_{safe_target}_"
                                 f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")

    ss = _styles()
    doc = SimpleDocTemplate(path, pagesize=A4, topMargin=18 * mm, bottomMargin=16 * mm)
    story = []

    # ── Header ──
    story.append(Paragraph("Security Compliance Evidence", ss["NSTitle"]))
    story.append(Paragraph(f"{framework_name(framework)}", ss["NSH2"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"<b>Organization:</b> {_org_name()}<br/>"
        f"<b>Target / scope:</b> {target}<br/>"
        f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M')}<br/>"
        f"<b>Source:</b> Continuous automated security monitoring by NullShadow v5.0",
        ss["NSMeta"]))
    story.append(Spacer(1, 12))

    # ── Executive summary ──
    story.append(Paragraph("1. Executive Summary", ss["NSH2"]))
    posture_rows = db.get_posture_history(target)
    latest_posture = posture_rows[-1]["posture_score"] if posture_rows else "N/A"
    story.append(Paragraph(
        f"This document provides audit evidence of ongoing technical security "
        f"monitoring for <b>{target}</b>, generated directly from {len(scans)} recorded "
        f"scan(s). A total of <b>{summary['total_findings']}</b> findings were assessed and "
        f"mapped to <b>{summary['controls_evidenced']}</b> {framework} control(s). "
        f"The most recent security posture score is <b>{latest_posture}/100</b>. "
        f"The existence of a dated scan history itself evidences continuous "
        f"monitoring requirements.", ss["NSBody"]))
    story.append(Spacer(1, 10))

    # ── Monitoring activity log ──
    story.append(Paragraph("2. Monitoring Activity Log", ss["NSH2"]))
    log_data = [["Scan ID", "Type", "Date", "Posture"]]
    for s in scans[:25]:
        log_data.append([str(s["id"]), s["scan_type"], str(s["timestamp"])[:16],
                         str(s["posture_score"]) if s["posture_score"] is not None else "—"])
    if len(log_data) == 1:
        log_data.append(["—", "No scans recorded", "—", "—"])
    story.append(_table(log_data, ss, col_widths=[20 * mm, 45 * mm, 45 * mm, 25 * mm]))
    story.append(Spacer(1, 10))

    # ── Findings mapped to controls ──
    story.append(Paragraph("3. Findings Mapped to Controls", ss["NSH2"]))
    fdata = [["Severity", "Finding", "Mapped control(s)"]]
    for f in summary["mapped"][:60]:
        ctrls = "; ".join(f.get("controls", [])) or "—"
        fdata.append([(f.get("severity") or "INFO"),
                      Paragraph(str(f.get("title", ""))[:70], ss["NSBody"]),
                      Paragraph(ctrls, ss["NSBody"])])
    if len(fdata) == 1:
        fdata.append(["—", "No findings recorded", "—"])
    story.append(_table(fdata, ss, col_widths=[20 * mm, 65 * mm, 80 * mm]))
    story.append(PageBreak())

    # ── Control coverage ──
    story.append(Paragraph("4. Control Coverage Statement", ss["NSH2"]))
    cov = [["Control", "Evidenced by (finding count)"]]
    for c in sorted(summary["coverage"].keys()):
        ids = summary["coverage"][c]
        cov.append([Paragraph(c, ss["NSBody"]),
                    "Continuous monitoring" if not ids else str(len(ids))])
    story.append(_table(cov, ss, col_widths=[110 * mm, 55 * mm]))
    story.append(Spacer(1, 12))

    # ── Statement of continuous monitoring ──
    story.append(Paragraph("5. Statement of Continuous Monitoring", ss["NSH2"]))
    story.append(Paragraph(
        "The findings and posture scores in this report were produced by automated, "
        "repeatable security scans scheduled and executed by NullShadow. The dated scan "
        "history constitutes documented evidence of ongoing vulnerability identification "
        "and security posture monitoring, satisfying the continuous-monitoring intent of "
        f"{framework_name(framework)}. Resolved findings across successive scans provide "
        "evidence of remediation and continual improvement.", ss["NSBody"]))
    story.append(Spacer(1, 16))
    story.append(Paragraph(
        "Generated from continuous automated security monitoring by NullShadow v5.0. "
        "For authorized assessment of in-scope systems only.", ss["NSMeta"]))

    doc.build(story)
    return path


def _table(data, ss, col_widths=None):
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f4f4")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


if __name__ == "__main__":
    from null_db.db import ScanDatabase
    db = ScanDatabase()
    s1 = db.save_scan("compliance.local", "Monitor", {})
    db.update_scan_monitor(s1, posture_score=72, alert_status="OK", risk_delta=0)
    db.add_finding(target="compliance.local", finding_type="vulnerability", title="Outdated OpenSSL",
                   severity="HIGH", cve_ids=["CVE-2014-0160"], raw_data={}, scan_id=s1)
    db.add_finding(target="compliance.local", finding_type="ssl_audit", title="Weak TLS version",
                   severity="MEDIUM", raw_data={}, scan_id=s1)
    db.add_finding(target="compliance.local", finding_type="sqli", title="SQLi in ?id param",
                   severity="HIGH", raw_data={}, scan_id=s1)
    p = generate_report("compliance.local", "ISO27001", db)
    print("PDF generated:", p, "| exists:", os.path.exists(p), "| size:", os.path.getsize(p))
