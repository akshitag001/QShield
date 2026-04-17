"""
report_pdf.py — Q-Shield PDF Report Generator
Uses ReportLab to generate a professional scan report from latest_report.json.
No external system libraries required (unlike WeasyPrint).
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).parent
LATEST_REPORT_PATH = BASE_DIR / "latest_report.json"
OUTPUT_PDF_PATH = BASE_DIR / "qshield_report.pdf"

# ---------------------------------------------------------------------------
# Brand colors
# ---------------------------------------------------------------------------
BRAND_DARK   = colors.HexColor("#0b3d91")   # Navy blue (header / headings)
BRAND_ACCENT = colors.HexColor("#1976D2")   # Lighter blue (sub-headings)
RISK_CRITICAL= colors.HexColor("#D32F2F")
RISK_HIGH    = colors.HexColor("#F57C00")
RISK_MEDIUM  = colors.HexColor("#FBC02D")
RISK_LOW     = colors.HexColor("#388E3C")
BG_LIGHT     = colors.HexColor("#F5F8FF")
BORDER_COLOR = colors.HexColor("#BBDEFB")


# ---------------------------------------------------------------------------
# Style helpers
# ---------------------------------------------------------------------------
def _styles():
    base = getSampleStyleSheet()

    title = ParagraphStyle(
        "QTitle",
        parent=base["Title"],
        fontSize=26,
        textColor=BRAND_DARK,
        spaceAfter=6,
        fontName="Helvetica-Bold",
    )
    subtitle = ParagraphStyle(
        "QSubtitle",
        parent=base["Normal"],
        fontSize=13,
        textColor=BRAND_ACCENT,
        spaceAfter=4,
        fontName="Helvetica",
    )
    section = ParagraphStyle(
        "QSection",
        parent=base["Heading1"],
        fontSize=14,
        textColor=BRAND_DARK,
        spaceBefore=14,
        spaceAfter=6,
        fontName="Helvetica-Bold",
        borderPad=4,
    )
    sub = ParagraphStyle(
        "QSub",
        parent=base["Heading2"],
        fontSize=11,
        textColor=BRAND_ACCENT,
        spaceBefore=8,
        spaceAfter=4,
        fontName="Helvetica-Bold",
    )
    body = ParagraphStyle(
        "QBody",
        parent=base["Normal"],
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor("#1A1A1A"),
        fontName="Helvetica",
    )
    small = ParagraphStyle(
        "QSmall",
        parent=body,
        fontSize=8,
        textColor=colors.grey,
    )
    label = ParagraphStyle(
        "QLabel",
        parent=body,
        fontSize=8.5,
        fontName="Helvetica-Bold",
        textColor=BRAND_DARK,
    )
    return title, subtitle, section, sub, body, small, label


# ---------------------------------------------------------------------------
# Risk color helper
# ---------------------------------------------------------------------------
def _risk_color(level: str):
    level = (level or "").upper()
    return {
        "CRITICAL": RISK_CRITICAL,
        "HIGH": RISK_HIGH,
        "MEDIUM": RISK_MEDIUM,
        "LOW": RISK_LOW,
    }.get(level, colors.grey)


# ---------------------------------------------------------------------------
# Header / Footer
# ---------------------------------------------------------------------------
def _header_footer(canvas, doc):
    canvas.saveState()
    w, h = A4

    # Top bar
    canvas.setFillColor(BRAND_DARK)
    canvas.rect(0, h - 28, w, 28, fill=1, stroke=0)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 10)
    canvas.drawString(20, h - 19, "Q-Shield  |  Cryptographic Inventory Report")
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(w - 20, h - 19, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))

    # Bottom bar
    canvas.setFillColor(BRAND_DARK)
    canvas.rect(0, 0, w, 20, fill=1, stroke=0)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(20, 6, "INTERNAL — CONFIDENTIAL")
    canvas.drawRightString(w - 20, 6, f"Page {doc.page}")

    canvas.restoreState()


# ---------------------------------------------------------------------------
# Main generate function
# ---------------------------------------------------------------------------
def generate_pdf(
    report_data: dict | None = None,
    output_path: Path | str | None = None,
) -> str:
    """
    Read latest_report.json (or accept a dict directly) and produce a PDF.

    Returns the absolute path of the generated PDF as a string.
    """
    # Resolve data
    if report_data is None:
        if not LATEST_REPORT_PATH.exists():
            raise FileNotFoundError(
                f"No scan data found at {LATEST_REPORT_PATH}. "
                "Run a scan first."
            )
        with open(LATEST_REPORT_PATH, encoding="utf-8") as fh:
            report_data = json.load(fh)

    # Resolve output path
    out = Path(output_path) if output_path else OUTPUT_PDF_PATH

    # ------------------------------------------------------------------ #
    # Extract fields
    # ------------------------------------------------------------------ #
    scan_id      = report_data.get("scan_id", "N/A")
    target       = report_data.get("target", "Unknown")
    started_at   = report_data.get("started_at", "N/A")
    status       = report_data.get("status", "unknown")
    result       = report_data.get("result", {}) or {}
    cbom         = report_data.get("cbom", {}) or {}
    summary      = cbom.get("summary", {}) or {}
    endpoints    = cbom.get("endpoints", []) or []

    # vulnerabilities can be either a bare list or the dict returned by
    # _extract_quantum_vulnerabilities  → {scan_id, target, total_vulnerabilities, vulnerabilities:[]}
    raw_vulns = report_data.get("vulnerabilities") or []
    if isinstance(raw_vulns, dict):
        vulns = raw_vulns.get("vulnerabilities", []) or []
    elif isinstance(raw_vulns, list):
        vulns = raw_vulns
    else:
        vulns = []

    # result and cbom may arrive as JSON strings (from the DB row) — parse them
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except Exception:
            result = {}
    if isinstance(cbom, str):
        try:
            cbom = json.loads(cbom)
            summary  = cbom.get("summary", {}) or {}
            endpoints = cbom.get("endpoints", []) or []
        except Exception:
            cbom = {}


    # ------------------------------------------------------------------ #
    # Build document
    # ------------------------------------------------------------------ #
    doc = SimpleDocTemplate(
        str(out),
        pagesize=A4,
        leftMargin=1.8 * cm,
        rightMargin=1.8 * cm,
        topMargin=2.2 * cm,
        bottomMargin=1.8 * cm,
    )

    T, Sub2, Sec, SubH, Body, Small, Label = _styles()
    story = []

    # ============================================================
    # COVER PAGE
    # ============================================================
    story.append(Spacer(1, 3 * cm))
    story.append(Paragraph("CRYPTOGRAPHIC BILL OF MATERIALS", T))
    story.append(Paragraph("Post-Quantum Cryptography Readiness Report", Sub2))
    story.append(Spacer(1, 0.5 * cm))
    story.append(HRFlowable(width="100%", thickness=2, color=BRAND_DARK))
    story.append(Spacer(1, 0.5 * cm))

    cover_data = [
        ["Target System", target],
        ["Scan ID", scan_id],
        ["Scan Date", started_at],
        ["Status", status.upper()],
        ["Generator", "Q-Shield CBOM Tool v1.6"],
        ["Classification", "INTERNAL — CONFIDENTIAL"],
    ]
    cover_table = Table(cover_data, colWidths=[5 * cm, 12 * cm])
    cover_table.setStyle(TableStyle([
        ("FONTNAME",    (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE",    (0, 0), (-1, -1), 10),
        ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
        ("TEXTCOLOR",   (0, 0), (0, -1), BRAND_DARK),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [BG_LIGHT, colors.white]),
        ("GRID",        (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("INNERGRID",   (0, 0), (-1, -1), 0.4, BORDER_COLOR),
        ("TOPPADDING",  (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(cover_table)
    story.append(PageBreak())

    # ============================================================
    # SECTION 1 — Executive Summary
    # ============================================================
    story.append(Paragraph("1. Executive Summary", Sec))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_DARK, spaceAfter=6))

    total_assets  = summary.get("total_assets", 0)
    vuln_assets   = summary.get("quantum_vulnerable_assets", 0)
    safe_assets   = summary.get("quantum_safe_assets", 0)
    pqc_score     = summary.get("pqc_readiness_score", 0)
    risk_severity = cbom.get("risk_summary", {}).get("severity", "UNKNOWN")

    exec_data = [
        ["Metric",                     "Value",           "Status"],
        ["Total Cryptographic Assets", str(total_assets), "Tracked"],
        ["Quantum Vulnerable Assets",  str(vuln_assets),  "⚠ ACTION REQUIRED"],
        ["Quantum Safe Assets",        str(safe_assets),  "✓ COMPLIANT"],
        ["PQC Readiness Score",        f"{pqc_score}%",   "Target: 100% by 2035"],
        ["Overall Risk Severity",      risk_severity,     "See Section 3"],
    ]
    exec_table = Table(exec_data, colWidths=[7 * cm, 4 * cm, 6 * cm])
    exec_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), BRAND_DARK),
        ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [BG_LIGHT, colors.white]),
        ("GRID",        (0, 0), (-1, -1), 0.4, BORDER_COLOR),
        ("TOPPADDING",  (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(exec_table)
    story.append(Spacer(1, 0.4 * cm))

    story.append(Paragraph(
        "This CBOM provides a comprehensive inventory of cryptographic assets discovered "
        "during automated TLS scanning and readiness for post-quantum migration.",
        Body,
    ))

    # ============================================================
    # SECTION 2 — TLS / Connection Details
    # ============================================================
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph("2. TLS Connection Details", Sec))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_DARK, spaceAfter=6))

    tls_version    = result.get("tls_version", "N/A")
    cipher         = result.get("cipher_suite", result.get("cipher", "N/A"))
    key_exchange   = result.get("key_exchange", "N/A")
    pqc_ready      = result.get("pqc_ready", False)
    hybrid          = result.get("hybrid_key_exchange", False)
    agility_score  = result.get("crypto_agility_score", result.get("agility_score", "N/A"))

    tls_data = [
        ["Parameter",        "Value"],
        ["TLS Version",      str(tls_version)],
        ["Cipher Suite",     str(cipher)],
        ["Key Exchange",     str(key_exchange)],
        ["PQC Ready",        "Yes ✓" if pqc_ready else "No ✗"],
        ["Hybrid Key Exch.", "Yes" if hybrid else "No"],
        ["Crypto Agility",   f"{agility_score} / 100"],
    ]
    tls_table = Table(tls_data, colWidths=[6 * cm, 11 * cm])
    tls_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), BRAND_DARK),
        ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME",    (0, 1), (0, -1), "Helvetica-Bold"),
        ("TEXTCOLOR",   (0, 1), (0, -1), BRAND_DARK),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [BG_LIGHT, colors.white]),
        ("GRID",        (0, 0), (-1, -1), 0.4, BORDER_COLOR),
        ("TOPPADDING",  (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(tls_table)

    # ============================================================
    # SECTION 3 — Quantum Vulnerabilities
    # ============================================================
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph("3. Quantum Vulnerability Findings", Sec))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_DARK, spaceAfter=6))

    if not vulns:
        story.append(Paragraph(
            "✓ No quantum vulnerabilities detected for this scan target.",
            Body,
        ))
    else:
        vuln_data = [["#", "Asset Type", "Name", "Risk", "Description", "Recommendation"]]
        for i, v in enumerate(vulns, 1):
            risk  = v.get("risk_level", "MEDIUM")
            vuln_data.append([
                str(i),
                v.get("asset_type", "—"),
                v.get("name", "—"),
                risk,
                Paragraph(v.get("description", "—"), Small),
                Paragraph(v.get("recommendation", "—"), Small),
            ])

        col_w = [0.8*cm, 2.5*cm, 3*cm, 1.8*cm, 5*cm, 4*cm]
        vuln_table = Table(vuln_data, colWidths=col_w, repeatRows=1)

        ts = [
            ("BACKGROUND",    (0, 0), (-1, 0), BRAND_DARK),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [BG_LIGHT, colors.white]),
            ("GRID",          (0, 0), (-1, -1), 0.4, BORDER_COLOR),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ]
        # Color the risk column cells
        for row_i, v in enumerate(vulns, 1):
            risk = (v.get("risk_level") or "MEDIUM").upper()
            c = _risk_color(risk)
            ts.append(("TEXTCOLOR", (3, row_i), (3, row_i), c))
            ts.append(("FONTNAME",  (3, row_i), (3, row_i), "Helvetica-Bold"))

        vuln_table.setStyle(TableStyle(ts))
        story.append(vuln_table)

    # ============================================================
    # SECTION 4 — Remediation Roadmap
    # ============================================================
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph("4. Remediation Roadmap", Sec))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_DARK, spaceAfter=6))

    roadmap = [
        ["Timeline",     "Action",                                           "Priority"],
        ["Q2–Q4 2026",   "Expand hybrid ML-KEM support across TLS 1.3",     "HIGH"],
        ["2027",         "Deploy ML-DSA certificate pilots from internal CA","HIGH"],
        ["2028–2029",    "Hybrid ML-KEM + ML-DSA on customer-facing svcs",  "MEDIUM"],
        ["2030",         "Deprecate RSA-only chains; full NIST alignment",   "HIGH"],
        ["2031–2035",    "Retire classical-only cryptography",               "MEDIUM"],
    ]
    road_table = Table(roadmap, colWidths=[3.5*cm, 11*cm, 2.5*cm])
    road_table.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0), BRAND_DARK),
        ("TEXTCOLOR",      (0, 0), (-1, 0), colors.white),
        ("FONTNAME",       (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME",       (0, 1), (0, -1), "Helvetica-Bold"),
        ("TEXTCOLOR",      (0, 1), (0, -1), BRAND_DARK),
        ("FONTSIZE",       (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [BG_LIGHT, colors.white]),
        ("GRID",           (0, 0), (-1, -1), 0.4, BORDER_COLOR),
        ("TOPPADDING",     (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 6),
        ("LEFTPADDING",    (0, 0), (-1, -1), 8),
    ]))
    story.append(road_table)

    # ============================================================
    # SECTION 5 — Audit Trail
    # ============================================================
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph("5. Audit Trail", Sec))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_DARK, spaceAfter=6))

    story.append(Paragraph(
        f"<b>Report Generated:</b> {datetime.now(timezone.utc).isoformat()}<br/>"
        f"<b>Generator:</b> Q-Shield CBOM Assessment Tool v1.6<br/>"
        f"<b>Compliance:</b> NIST FIPS 203/204/205 · NSA CNSA 2.0<br/>"
        f"<b>Scan ID:</b> {scan_id}",
        Body,
    ))
    story.append(Spacer(1, 0.6 * cm))
    story.append(Paragraph(
        "<i>Disclaimer: This CBOM represents cryptographic assets discovered during automated scanning. "
        "Regenerate after infrastructure changes or at least quarterly.</i>",
        Small,
    ))

    # ================================================================
    # Build PDF
    # ================================================================
    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return str(out.resolve())


# ---------------------------------------------------------------------------
# Convenience: run directly
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    path = generate_pdf()
    print(f"PDF saved to: {path}")
