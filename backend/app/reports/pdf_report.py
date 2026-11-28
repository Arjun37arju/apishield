from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
SEVERITY_COLOR = {
    "Critical": colors.HexColor("#7f1d1d"),
    "High": colors.HexColor("#b91c1c"),
    "Medium": colors.HexColor("#c2410c"),
    "Low": colors.HexColor("#a16207"),
    "Info": colors.HexColor("#475569"),
}
OUTCOME_COLOR = {
    "Passed": colors.HexColor("#15803d"),
    "Finding": colors.HexColor("#b91c1c"),
    "Error": colors.HexColor("#7f1d1d"),
    "Skipped": colors.HexColor("#64748b"),
    "Needs manual check": colors.HexColor("#a16207"),
}

styles = getSampleStyleSheet()
BODY = ParagraphStyle("body", parent=styles["BodyText"], fontSize=9.5, leading=13)
SMALL = ParagraphStyle("small", parent=BODY, fontSize=8, leading=10)
MONO = ParagraphStyle("mono", parent=BODY, fontName="Courier", fontSize=7.5, leading=9.5)
H1 = ParagraphStyle("h1", parent=styles["Title"], fontSize=22, spaceAfter=6)
H2 = ParagraphStyle("h2", parent=styles["Heading2"], spaceBefore=12, spaceAfter=6)
H3 = ParagraphStyle("h3", parent=styles["Heading3"], fontSize=11, spaceAfter=3)


def _p(text, style=BODY, limit=None):
    text = str(text if text is not None else "")
    if limit and len(text) > limit:
        text = text[:limit] + " ... (shortened)"
    return Paragraph(escape(text), style)


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.grey)
    canvas.drawString(18 * mm, 10 * mm, "API-Gapwolf report - confidential")
    canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, "Page %d" % doc.page)
    canvas.restoreState()


def _count_by(items, key, order):
    counts = {k: 0 for k in order}
    for it in items:
        value = it.get(key)
        if value in counts:
            counts[value] += 1
    return counts


def _summary_table(scan):
    findings = scan.get("findings") or []
    sev = _count_by(findings, "severity", SEVERITY_ORDER)
    rows = [
        ["Target", scan.get("scope", "")],
        ["Scan ID", scan.get("id", "")],
        ["Started", scan.get("started_at", "")],
        ["Finished", scan.get("finished_at", "")],
        ["Status", scan.get("state", "")],
        ["Requests sent", str(scan.get("requests_made", 0))],
        ["Findings", str(len(findings))
         + "  (" + ", ".join("%s %d" % (k, v) for k, v in sev.items() if v) + ")"
         if findings else "0"],
    ]
    table = Table([[_p(a, SMALL), _p(b, BODY)] for a, b in rows],
                  colWidths=[35 * mm, 135 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return table

def _default_message(outcome):
    if outcome == "Finding":
        return "See the findings section."
    if outcome == "Passed":
        return "No problem seen."
    return ""

def _checks_table(scan):
    rows = [[_p("Check", SMALL), _p("Result", SMALL), _p("Details", SMALL)]]
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    for i, r in enumerate(scan.get("results") or [], start=1):
        outcome = r.get("outcome", "")
        rows.append([
            _p(r.get("name") or r.get("check_id", ""), SMALL),
            _p(outcome, SMALL),
            _p(r.get("message") or _default_message(outcome), SMALL, limit=160),
        ])
        style.append(("TEXTCOLOR", (1, i), (1, i), OUTCOME_COLOR.get(outcome, colors.black)))
    table = Table(rows, colWidths=[62 * mm, 28 * mm, 80 * mm], repeatRows=1)
    table.setStyle(TableStyle(style))
    return table


def _finding_block(f):
    sev = f.get("severity", "Info")
    head = Table(
        [[_p(f.get("id", ""), H3), _p(sev, H3),
          _p("Confidence: " + str(f.get("confidence", "")), SMALL)]],
        colWidths=[25 * mm, 25 * mm, 120 * mm],
    )
    head.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("TEXTCOLOR", (1, 0), (1, 0), SEVERITY_COLOR.get(sev, colors.black)),
        ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
    ]))
    ev = f.get("evidence") or {}
    req = ev.get("request") or {}
    resp = ev.get("response") or {}
    evidence_lines = []
    if req:
        evidence_lines.append("Request: %s %s" % (req.get("method", ""), req.get("url", "")))
    if resp:
        evidence_lines.append("Response status: %s" % resp.get("status", ""))
        if resp.get("body"):
            evidence_lines.append("Response body: " + str(resp.get("body")))
    parts = [
        head,
        Spacer(1, 2),
        _p(f.get("title", ""), BODY),
        _p("Category: %s   |   Endpoint: %s   |   Status: %s" % (
            f.get("category", ""), f.get("endpoint", ""), f.get("status", "")), SMALL),
        Spacer(1, 3),
        _p("Impact: " + str(f.get("impact", "")), BODY),
        _p("Fix: " + str(f.get("fix", "")), BODY),
    ]
    if evidence_lines:
        parts.append(Spacer(1, 3))
        parts.append(_p("Evidence (secrets are masked)", SMALL))
        for line in evidence_lines:
            parts.append(_p(line, MONO, limit=500))
    parts.append(Spacer(1, 10))
    return KeepTogether(parts)


def build_report(scan, out_dir):
    """Build a PDF from a scan dict (same shape as the scan API returns).
    Returns the Path of the new file."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / ("api-gapwolf-report-" + str(scan.get("id", "scan")) + ".pdf")

    doc = SimpleDocTemplate(
        str(path), pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm, title="API-Gapwolf report",
    )
    findings = list(scan.get("findings") or [])
    findings.sort(key=lambda f: SEVERITY_ORDER.index(f.get("severity"))
                  if f.get("severity") in SEVERITY_ORDER else 99)

    story = [
        _p("API-Gapwolf Security Report", H1),
        _p("Generated " + datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), SMALL),
        Spacer(1, 8),
        _p("Summary", H2),
        _summary_table(scan),
        Spacer(1, 6),
        _p("Findings marked 'suspected' or 'manual review' need a person to confirm "
           "them. A scan without a finding does not prove the API is safe.", SMALL),
        _p("Check results", H2),
        _checks_table(scan),
        _p("Findings (%d)" % len(findings), H2),
    ]
    if not findings:
        story.append(_p("No findings were recorded for this scan."))
    for f in findings:
        story.append(_finding_block(f))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return path