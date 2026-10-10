"""PDF report generation with ReportLab."""
from __future__ import annotations

import io
from collections import OrderedDict
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer,
                                Table, TableStyle)

SEV_COLORS = {
    "critical": colors.HexColor("#b91c1c"),
    "high": colors.HexColor("#ea580c"),
    "medium": colors.HexColor("#ca8a04"),
    "low": colors.HexColor("#2563eb"),
    "info": colors.HexColor("#64748b"),
    "pass": colors.HexColor("#15803d"),
}
GRADE_COLORS = {"A": "#15803d", "B": "#65a30d", "C": "#ca8a04", "D": "#ea580c", "F": "#b91c1c"}
NAVY = colors.HexColor("#0f172a")
GREY = colors.HexColor("#475569")
LIGHT = colors.HexColor("#f1f5f9")

CATEGORY_ORDER = ["DNS", "DNSSEC", "SSL/TLS", "Certificate expiry", "HTTP headers", "Email authentication",
                  "Subdomains", "Exposed services", "Security configuration", "Privacy (preview)"]


def _p(text, style):
    return Paragraph(escape(str(text)), style)


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(GREY)
    canvas.drawString(18 * mm, 10 * mm, f"Passive security assessment - {doc.domain}")
    canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def build_pdf(result: dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=18 * mm, bottomMargin=18 * mm,
                            title=f"Security assessment - {result['domain']}", author="SME Security Scanner")
    doc.domain = result["domain"]
    width = A4[0] - 36 * mm

    ss = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=ss["BodyText"], fontSize=9.5, leading=13, textColor=NAVY)
    small = ParagraphStyle("small", parent=body, fontSize=8.5, leading=11.5, textColor=GREY)
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], fontSize=17, textColor=NAVY, spaceAfter=6, spaceBefore=4)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontSize=12.5, textColor=NAVY, spaceBefore=12, spaceAfter=5)
    title = ParagraphStyle("title", parent=h1, fontSize=26, leading=30)
    ftitle = ParagraphStyle("ftitle", parent=body, fontName="Helvetica-Bold", fontSize=9.5)
    badge = ParagraphStyle("badge", parent=small, textColor=colors.white, fontName="Helvetica-Bold",
                           fontSize=7.5, alignment=TA_CENTER)

    story = []
    scanned = datetime.fromisoformat(result["scanned_at"]).strftime("%d %B %Y, %H:%M UTC")

    
    story += [Spacer(1, 10 * mm), _p("Passive Security Assessment", title),
              _p(result["domain"], ParagraphStyle("dom", parent=h1, fontSize=18, textColor=GREY)),
              _p(f"Scanned {scanned}", small), Spacer(1, 8 * mm)]

    g = result["grade"]
    grade_cell = Table([[Paragraph(f'<font size="48" color="white"><b>{escape(g)}</b></font>',
                                   ParagraphStyle("g", alignment=TA_CENTER, leading=54))],
                        [Paragraph(f'<font size="11" color="white">{result["score"]} / 100</font>',
                                   ParagraphStyle("gs", alignment=TA_CENTER)) if g != "?" else Paragraph(
                            '<font size="9" color="white">not graded</font>', ParagraphStyle("gs", alignment=TA_CENTER))]],
                       colWidths=[40 * mm])
    grade_cell.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(GRADE_COLORS.get(g, "#64748b"))),
                                    ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    c = result["counts"]
    num = ParagraphStyle("num", parent=badge, textColor=NAVY, fontSize=11, leading=11.5)
    count_rows = [[Paragraph(f'<font color="white"><b>{s.title()}</b></font>', badge),
                   Paragraph(str(c.get(s, 0)), num)]
                  for s in ("critical", "high", "medium", "low", "info", "pass")]
    count_tbl = Table(count_rows, colWidths=[24 * mm, 14 * mm])
    style = [("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("FONTSIZE", (1, 0), (1, -1), 11),
             ("FONTNAME", (1, 0), (1, -1), "Helvetica-Bold"), ("TOPPADDING", (0, 0), (-1, -1), 3),
             ("BOTTOMPADDING", (0, 0), (-1, -1), 3), ("ALIGN", (1, 0), (1, -1), "CENTER")]
    for i, s in enumerate(("critical", "high", "medium", "low", "info", "pass")):
        style.append(("BACKGROUND", (0, i), (0, i), SEV_COLORS[s]))
    count_tbl.setStyle(TableStyle(style))
    top = Table([[grade_cell, count_tbl]], colWidths=[55 * mm, width - 55 * mm])
    top.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story += [top, Spacer(1, 8 * mm)]

    urgent = c.get("critical", 0) + c.get("high", 0)
    if urgent:
        summary = (f"This passive scan found {urgent} critical or high-severity issue(s) that should be fixed first, "
                   f"plus {c.get('medium', 0)} medium and {c.get('low', 0)} low-severity items. "
                   "Most can be resolved with DNS and web-server configuration changes rather than new software.")
    elif c.get("medium", 0):
        summary = (f"No critical or high-severity issues were found. {c.get('medium', 0)} medium-severity item(s) "
                   "would meaningfully strengthen your security posture.")
    else:
        summary = "No significant issues were found by this passive scan. Keep monitoring, especially certificate expiry and email authentication."
    story += [_p("Executive summary", h2), _p(summary, body), Spacer(1, 3 * mm),
              _p("The scan focuses on misconfiguration, exposed services and weak access controls: the everyday weaknesses "
                 "that national CERT advisories in Kenya (KE-CIRT/CC) have highlighted for organisations of all sizes.", body)]

    # priority actions
    prio = [f for f in result["findings"] if f["severity"] in ("critical", "high", "medium") and f.get("fix")][:8]
    if prio:
        story += [_p("Priority actions", h2)]
        rows = [[_p(str(i + 1), small), [_p(f["title"], ftitle), _p(f["fix"], small)]] for i, f in enumerate(prio)]
        t = Table(rows, colWidths=[8 * mm, width - 8 * mm])
        t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                               ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
        story.append(t)

    m = result.get("meta") or {}
    if m:
        story += [_p("At a glance", h2)]
        glance = [("Addresses", ", ".join(m.get("ips") or []) or "-"),
                  ("Nameservers", ", ".join(m.get("nameservers") or []) or "-"),
                  ("Mail servers", ", ".join(m.get("mx") or []) or "none"),
                  ("Certificate", f"expires {m['cert_expires']} ({m['cert_days_left']} days)" if m.get("cert_expires") else "-"),
                  ("TLS negotiated", m.get("tls_negotiated") or "-"),
                  ("Open-port check", "performed (owner confirmed authorisation)" if m.get("port_check") else "not performed")]
        t = Table([[_p(k, small), _p(v, body)] for k, v in glance], colWidths=[32 * mm, width - 32 * mm])
        t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("BACKGROUND", (0, 0), (0, -1), LIGHT),
                               ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey)]))
        story.append(t)
    story.append(PageBreak())

    
    story.append(_p("Detailed findings", h1))
    groups: "OrderedDict[str, list]" = OrderedDict()
    for cat in CATEGORY_ORDER:
        groups[cat] = []
    for f in result["findings"]:
        groups.setdefault(f["category"], []).append(f)
    for cat, items in groups.items():
        if not items:
            continue
        story.append(_p(cat, h2))
        rows = []
        for f in items:
            sev = f["severity"]
            cell = [_p(f["title"], ftitle)]
            if f.get("detail"):
                cell.append(_p(f["detail"], small))
            if f.get("fix"):
                cell.append(Paragraph("<b>Fix:</b> " + escape(f["fix"]), small))
            rows.append([Paragraph(sev.upper(), badge), cell])
        t = Table(rows, colWidths=[18 * mm, width - 18 * mm], repeatRows=0)
        st = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.lightgrey),
              ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]
        for i, f in enumerate(items):
            st.append(("BACKGROUND", (0, i), (0, i), SEV_COLORS.get(f["severity"], GREY)))
            st.append(("VALIGN", (0, i), (0, i), "MIDDLE"))
        t.setStyle(TableStyle(st))
        story.append(t)

    
    story.append(PageBreak())
    story.append(_p("Appendix A: Technology stack (detected)", h1))
    techs = result.get("technologies") or []
    if techs:
        t = Table([[_p("Technology", small), _p("Type", small)]] + [[_p(x["name"], body), _p(x["type"], body)] for x in techs],
                  colWidths=[width * 0.6, width * 0.4])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), LIGHT), ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey)]))
        story.append(t)
    else:
        story.append(_p("No technologies could be identified from public responses.", body))

    story.append(_p("Appendix B: Subdomains seen in public certificate logs", h2))
    subs = result.get("subdomains") or []
    if subs:
        rows = [[_p("Hostname", small), _p("Status", small), _p("Points to", small)]]
        for s in subs[:150]:
            status = "unchecked" if s.get("live") is None else "dangling" if s.get("dangling") else "resolves" if s["live"] else "no address"
            rows.append([_p(s["name"], small), _p(status, small), _p(s.get("cname") or ", ".join(s.get("ips") or []), small)])
        t = Table(rows, colWidths=[width * 0.5, width * 0.15, width * 0.35], repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), LIGHT), ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey)]))
        story.append(t)
        if len(subs) > 150:
            story.append(_p(f"...and {len(subs) - 150} more.", small))
    else:
        story.append(_p("None found.", body))

    story.append(KeepTogether([
        _p("Methodology and limitations", h2),
        _p("This is an automated, passive assessment. It uses public DNS, public certificate-transparency logs, a normal TLS "
           "handshake and ordinary page requests, with no exploitation, brute-forcing or credential attempts. An optional "
           "TCP-connect check of common service ports is performed only when the domain owner confirms authorisation.", body),
        Spacer(1, 2 * mm),
        _p("Passive results cannot see inside your network, applications, cloud accounts or devices, and DKIM selectors "
           "cannot be fully enumerated. A clean report is not a guarantee of security and is not a substitute for a "
           "penetration test or compliance audit. The privacy preview is an automated hint only and does not assess "
           "compliance with the Data Protection Act, 2019; refer to guidance from the Office of the Data Protection "
           "Commissioner (ODPC).", body),
    ]))
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()
