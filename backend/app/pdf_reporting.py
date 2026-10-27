from __future__ import annotations

import html
import io
import re
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    LongTable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.reporting import (
    SECTIONS,
    SEVERITY_ORDER,
    _exposure_observations,
    _safe_value,
    _vulnerability_findings,
)

NAVY = colors.HexColor("#14263F")
INK = colors.HexColor("#172033")
MUTED = colors.HexColor("#617187")
ACCENT = colors.HexColor("#2B63C8")
LINE = colors.HexColor("#D9E2ED")
PANEL = colors.HexColor("#F3F6FA")
WHITE = colors.white

SEVERITY_COLORS = {
    "Critical": (colors.HexColor("#FEE2E2"), colors.HexColor("#991B1B")),
    "High": (colors.HexColor("#FFEDD5"), colors.HexColor("#9A3412")),
    "Medium": (colors.HexColor("#FEF3C7"), colors.HexColor("#854D0E")),
    "Low": (colors.HexColor("#DCFCE7"), colors.HexColor("#166534")),
    "Informational": (colors.HexColor("#DBEAFE"), colors.HexColor("#1D4ED8")),
    "Unrated": (colors.HexColor("#E2E8F0"), colors.HexColor("#475569")),
}

PDF_COLUMNS = {
    "hosts": ("address", "name", "os_name", "os_flavor", "purpose"),
    "services": ("host", "port", "proto", "name", "state", "info"),
    "vulns": ("host", "port", "name", "severity", "refs"),
    "creds": ("host", "username", "service_name", "realm", "private_type"),
    "loot": ("host", "service", "name", "ltype", "created_at", "size"),
}


def _plain(value: Any) -> str:
    """Convert text to a safe, built-in-font-compatible PDF string."""
    text = str(value if value is not None else "—")
    text = (
        text.replace("\u2014", " - ")
        .replace("\u2013", "-")
        .replace("\u2011", "-")
        .replace("\u2022", "-")
        .replace("\u2018", "'")
        .replace("\u2019", "'")
        .replace("\u201c", '"')
        .replace("\u201d", '"')
        .replace("\u00a0", " ")
    )
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")


def _paragraph(value: Any, style: ParagraphStyle, *, already_safe: bool = False) -> Paragraph:
    text = _plain(value if already_safe else value)
    escaped = html.escape(text, quote=False).replace("\n", "<br/>")
    return Paragraph(escaped, style)


def _safe_paragraph(key: str, value: Any, style: ParagraphStyle, limit: int = 900) -> Paragraph:
    safe = _safe_value(key, value)
    if len(safe) > limit:
        safe = safe[: limit - 3] + "..."
    return _paragraph(safe, style, already_safe=True)


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "eyebrow": ParagraphStyle(
            "ReportEyebrow", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=8, leading=10, textColor=ACCENT, spaceAfter=4,
        ),
        "title": ParagraphStyle(
            "ReportTitle", parent=base["Title"], fontName="Helvetica-Bold",
            fontSize=25, leading=29, textColor=NAVY, alignment=TA_LEFT,
            spaceBefore=0, spaceAfter=8,
        ),
        "subtitle": ParagraphStyle(
            "ReportSubtitle", parent=base["Normal"], fontSize=9, leading=13,
            textColor=MUTED, spaceAfter=4,
        ),
        "section": ParagraphStyle(
            "ReportSection", parent=base["Heading2"], fontName="Helvetica-Bold",
            fontSize=14, leading=18, textColor=NAVY, spaceBefore=8, spaceAfter=6,
            keepWithNext=True,
        ),
        "subsection": ParagraphStyle(
            "ReportSubsection", parent=base["Heading3"], fontName="Helvetica-Bold",
            fontSize=10, leading=13, textColor=NAVY, spaceBefore=5, spaceAfter=4,
            keepWithNext=True,
        ),
        "body": ParagraphStyle(
            "ReportBody", parent=base["BodyText"], fontName="Helvetica",
            fontSize=8.5, leading=12, textColor=INK, spaceAfter=3,
        ),
        "small": ParagraphStyle(
            "ReportSmall", parent=base["BodyText"], fontName="Helvetica",
            fontSize=7.5, leading=10, textColor=INK,
        ),
        "muted": ParagraphStyle(
            "ReportMuted", parent=base["BodyText"], fontName="Helvetica",
            fontSize=7.2, leading=9.2, textColor=MUTED,
        ),
        "card_label": ParagraphStyle(
            "ReportCardLabel", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=6.4, leading=8, textColor=MUTED, alignment=TA_LEFT,
        ),
        "card_value": ParagraphStyle(
            "ReportCardValue", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=20, leading=23, textColor=NAVY, alignment=TA_LEFT,
        ),
        "table_head": ParagraphStyle(
            "ReportTableHead", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=6.7, leading=8, textColor=WHITE,
        ),
        "table_cell": ParagraphStyle(
            "ReportTableCell", parent=base["Normal"], fontName="Helvetica",
            fontSize=6.6, leading=8.2, textColor=INK, wordWrap="CJK",
        ),
        "finding_title": ParagraphStyle(
            "ReportFindingTitle", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=9, leading=12, textColor=NAVY,
        ),
        "finding_label": ParagraphStyle(
            "ReportFindingLabel", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=7, leading=9, textColor=MUTED,
        ),
        "severity": ParagraphStyle(
            "ReportSeverity", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=7, leading=9, alignment=TA_CENTER,
        ),
        "notice": ParagraphStyle(
            "ReportNotice", parent=base["Normal"], fontName="Helvetica",
            fontSize=7.3, leading=10, textColor=MUTED,
        ),
    }


def _section_heading(title: str, styles: dict[str, ParagraphStyle]) -> list[Any]:
    return [
        Spacer(1, 7),
        _paragraph(title, styles["section"]),
        HRFlowable(width="100%", thickness=0.6, color=LINE, spaceAfter=8),
    ]


def _metric_cards(
    metrics: list[tuple[str, int]],
    available_width: float,
    styles: dict[str, ParagraphStyle],
) -> Table:
    gap = 6
    card_width = (available_width - gap * 2) / 3
    cells: list[Table] = []
    for label, value in metrics:
        card = Table(
            [[_paragraph(label.upper(), styles["card_label"])],
             [_paragraph(value, styles["card_value"])]],
            colWidths=[card_width],
        )
        card.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), PANEL),
            ("BOX", (0, 0), (-1, -1), 0.6, LINE),
            ("LEFTPADDING", (0, 0), (-1, -1), 9),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, 0), 8),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 3),
            ("TOPPADDING", (0, 1), (-1, 1), 0),
            ("BOTTOMPADDING", (0, 1), (-1, 1), 8),
        ]))
        cells.append(card)

    rows = []
    for start in range(0, len(cells), 3):
        group = cells[start:start + 3]
        while len(group) < 3:
            group.append("")
        rows.append(group)
    table = Table(rows, colWidths=[card_width] * 3, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), gap),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), gap),
    ]))
    return table


def _severity_table(
    counts: dict[str, int],
    available_width: float,
    styles: dict[str, ParagraphStyle],
) -> Table:
    cell_width = available_width / len(SEVERITY_ORDER)
    header_row = []
    count_row = []
    for level in SEVERITY_ORDER:
        background, text_color = SEVERITY_COLORS[level]
        header_row.append(_paragraph(level, ParagraphStyle(
            f"SeverityHeader{level}", parent=styles["table_cell"],
            fontName="Helvetica-Bold", fontSize=6.6, leading=8,
            textColor=text_color, alignment=TA_CENTER,
        )))
        count_row.append(_paragraph(counts[level], ParagraphStyle(
            f"SeverityCount{level}", parent=styles["card_value"],
            fontSize=14, leading=17, textColor=text_color, alignment=TA_CENTER,
        )))
    table = Table([header_row, count_row], colWidths=[cell_width] * len(SEVERITY_ORDER))
    commands = [
        ("BOX", (0, 0), (-1, -1), 0.5, LINE),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, 0), 7),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 5),
        ("TOPPADDING", (0, 1), (-1, 1), 5),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 8),
    ]
    for index, level in enumerate(SEVERITY_ORDER):
        background, _ = SEVERITY_COLORS[level]
        commands.append(("BACKGROUND", (index, 0), (index, 0), background))
        commands.append(("BACKGROUND", (index, 1), (index, 1), colors.white))
    table.setStyle(TableStyle(commands))
    return table


def _finding_card(item: dict[str, str], styles: dict[str, ParagraphStyle], width: float) -> Table:
    fill, severity_color = SEVERITY_COLORS.get(item["severity"], SEVERITY_COLORS["Unrated"])
    severity_style = ParagraphStyle(
        f"FindingSeverity{item['severity']}", parent=styles["severity"], textColor=severity_color
    )
    title_width = width - 92
    header = Table(
        [[_paragraph(item["title"], styles["finding_title"]),
          _paragraph(item["severity"], severity_style)]],
        colWidths=[title_width, 92],
    )
    header.setStyle(TableStyle([
        ("BACKGROUND", (1, 0), (1, 0), fill),
        ("BOX", (1, 0), (1, 0), 0.4, fill),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))

    evidence = _paragraph(item["evidence"][:900], styles["small"], already_safe=True)
    remediation = _paragraph(item["remediation"][:900], styles["small"], already_safe=True)
    rows = [
        [header],
        [_paragraph(f"Host: {item['host']}    Port: {item['port']}    Score: {item['score']}", styles["muted"], already_safe=True)],
        [Table(
            [[_paragraph("RECORDED EVIDENCE", styles["finding_label"]), evidence]],
            colWidths=[94, width - 94],
            style=TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]),
        )],
        [Table(
            [[_paragraph("RECOMMENDED ACTION", styles["finding_label"]), remediation]],
            colWidths=[94, width - 94],
            style=TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]),
        )],
    ]
    card = Table(rows, colWidths=[width], hAlign="LEFT")
    card.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.6, LINE),
        ("BACKGROUND", (0, 0), (-1, -1), WHITE),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, 0), 6),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 5),
        ("TOPPADDING", (0, 1), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 3),
    ]))
    return card


def _inventory_table(
    key: str,
    rows: list[dict[str, Any]],
    width: float,
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    columns = PDF_COLUMNS.get(key, ())
    if not rows:
        return [_paragraph("No records in this workspace.", styles["muted"]), Spacer(1, 4)]

    visible = [record for record in rows[:1000] if isinstance(record, dict)]
    if not visible:
        return [_paragraph("No records in this workspace.", styles["muted"]), Spacer(1, 4)]

    data = [[_paragraph(column.replace("_", " ").title(), styles["table_head"]) for column in columns]]
    for record in visible:
        cells = []
        for column in columns:
            safe = _safe_value(column, record.get(column))
            # Smaller inventory cells keep large metadata from overwhelming pages.
            if len(safe) > 280:
                safe = safe[:277] + "..."
            cells.append(_paragraph(safe, styles["table_cell"], already_safe=True))
        data.append(cells)

    column_width = width / len(columns)
    table = LongTable(
        data,
        colWidths=[column_width] * len(columns),
        repeatRows=1,
        hAlign="LEFT",
        splitByRow=1,
    )
    commands = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("GRID", (0, 0), (-1, -1), 0.35, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    for row_number in range(1, len(data)):
        if row_number % 2 == 0:
            commands.append(("BACKGROUND", (0, row_number), (-1, row_number), PANEL))
    table.setStyle(TableStyle(commands))
    result: list[Any] = [table]
    if len(rows) > len(visible):
        result.append(_paragraph(f"Showing the first {len(visible)} of {len(rows)} records.", styles["muted"]))
    result.append(Spacer(1, 5))
    return result


def _page_decor(canvas_obj: canvas.Canvas, doc: SimpleDocTemplate) -> None:
    canvas_obj.saveState()
    page_width, page_height = A4
    canvas_obj.setStrokeColor(LINE)
    canvas_obj.setLineWidth(0.6)
    canvas_obj.line(doc.leftMargin, page_height - 29, page_width - doc.rightMargin, page_height - 29)
    canvas_obj.setFont("Helvetica-Bold", 7)
    canvas_obj.setFillColor(NAVY)
    canvas_obj.drawString(doc.leftMargin, page_height - 22, "MSF WEB CONSOLE")
    canvas_obj.setFont("Helvetica", 7)
    canvas_obj.setFillColor(MUTED)
    canvas_obj.drawRightString(page_width - doc.rightMargin, page_height - 22, "ASSESSMENT REPORT")
    canvas_obj.line(doc.leftMargin, 34, page_width - doc.rightMargin, 34)
    canvas_obj.setFont("Helvetica", 6.8)
    canvas_obj.setFillColor(MUTED)
    canvas_obj.drawString(doc.leftMargin, 22, "CONFIDENTIAL - Handle this report as sensitive assessment data.")
    canvas_obj.drawRightString(page_width - doc.rightMargin, 22, f"Page {doc.page}")
    canvas_obj.restoreState()


def build_assessment_report_pdf(workspace: str, records: dict[str, list[dict[str, Any]]]) -> bytes:
    """Build a native, downloadable PDF assessment report using the same redaction rules as HTML."""
    output = io.BytesIO()
    page_width, _ = A4
    left_margin = 16 * mm
    right_margin = 16 * mm
    top_margin = 43 * mm
    bottom_margin = 16 * mm
    available_width = page_width - left_margin - right_margin

    document = SimpleDocTemplate(
        output,
        pagesize=A4,
        leftMargin=left_margin,
        rightMargin=right_margin,
        topMargin=top_margin,
        bottomMargin=bottom_margin,
        title=f"MSF Assessment - {_plain(_safe_value('workspace', workspace or 'default'))}",
        author="MSF Web Console",
        subject="Read-only Metasploit workspace assessment snapshot",
        pageCompression=0,
    )
    styles = _styles()
    hosts = records.get("hosts", [])
    services = records.get("services", [])
    vulns = records.get("vulns", [])
    creds = records.get("creds", [])
    loot = records.get("loot", [])
    findings = _vulnerability_findings(vulns)
    observations = _exposure_observations(services)
    severity_counts = {level: sum(item["severity"] == level for item in findings) for level in SEVERITY_ORDER}
    rated_count = sum(severity_counts[level] for level in SEVERITY_ORDER if level != "Unrated")
    priority_points = sum(
        {"Critical": 10, "High": 7, "Medium": 4, "Low": 1}.get(item["severity"], 0)
        for item in findings
    )
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    safe_workspace = _safe_value("workspace", workspace or "default")

    summary_parts = []
    if findings:
        severity_text = ", ".join(
            f"{severity_counts[level]} {level.lower()}" for level in SEVERITY_ORDER if severity_counts[level]
        )
        summary_parts.append(f"The workspace contains {len(findings)} vulnerability record(s): {severity_text}.")
        if severity_counts["Unrated"]:
            summary_parts.append(
                f"{severity_counts['Unrated']} record(s) have no explicit severity or usable score and require manual triage."
            )
    else:
        summary_parts.append(
            "No vulnerability records were present in the database snapshot; this is not evidence that no vulnerabilities exist."
        )
    if observations:
        summary_parts.append(
            f"{len(observations)} service(s) were explicitly marked open. Review exposure and access controls; open state alone is not a vulnerability."
        )
    else:
        summary_parts.append("No service records were explicitly marked open in this snapshot.")

    story: list[Any] = [
        _paragraph("MSF WEB CONSOLE / ASSESSMENT", styles["eyebrow"]),
        _paragraph("Assessment Report", styles["title"]),
        _paragraph(f"Workspace: {_plain(safe_workspace)}", styles["subtitle"], already_safe=True),
        _paragraph(f"Generated {generated} - read-only snapshot of the active Metasploit database workspace.", styles["subtitle"]),
        Spacer(1, 5),
        HRFlowable(width="100%", thickness=1.2, color=ACCENT, spaceAfter=12),
        _paragraph("Executive Summary", styles["section"]),
        _paragraph(" ".join(summary_parts), styles["body"]),
        Spacer(1, 6),
        _paragraph("Workspace Inventory", styles["section"]),
    ]

    metrics = [
        ("Hosts", len(hosts)),
        ("Services", len(services)),
        ("Vulnerability records", len(vulns)),
        ("Open-service observations", len(observations)),
        ("Credential records", len(creds)),
        ("Loot records", len(loot)),
    ]
    story.extend([
        _metric_cards(metrics, available_width, styles),
        Spacer(1, 9),
        _paragraph("Severity Summary", styles["section"]),
        _severity_table(severity_counts, available_width, styles),
        Spacer(1, 5),
        _paragraph(
            f"Priority points: {priority_points}. This is a simple triage aid, not a CVSS score or quantified likelihood. "
            f"{rated_count} of {len(findings)} finding(s) have a recognized rating.",
            styles["muted"],
        ),
    ])

    story.extend(_section_heading("Prioritized Vulnerability Findings", styles))
    if not findings:
        story.extend([
            _paragraph(
                "No vulnerability records were present in this workspace snapshot. This does not prove the environment is free of vulnerabilities.",
                styles["muted"],
            ),
            Spacer(1, 4),
        ])
    else:
        for index, item in enumerate(findings[:1000], start=1):
            story.append(KeepTogether([
                _finding_card(item, styles, available_width),
                Spacer(1, 7),
            ]))
        if len(findings) > 1000:
            story.append(_paragraph(f"Showing the first 1,000 of {len(findings)} vulnerability records.", styles["muted"]))

    story.extend(_section_heading("Affected Hosts", styles))
    host_severity: dict[str, Counter[str]] = defaultdict(Counter)
    for finding in findings:
        host = finding["host"]
        if host and host != "Unknown host":
            host_severity[host][finding["severity"]] += 1
    if not host_severity:
        story.append(_paragraph("No affected hosts could be inferred from the vulnerability records.", styles["muted"]))
    else:
        host_header = ["Host", "Findings", "Critical", "High", "Medium", "Low", "Unrated"]
        host_data = [[_paragraph(item, styles["table_head"]) for item in host_header]]
        for host, counts in sorted(host_severity.items())[:1000]:
            host_data.append([
                _safe_paragraph("host", host, styles["table_cell"], 250),
                _paragraph(sum(counts.values()), styles["table_cell"]),
                _paragraph(counts["Critical"], styles["table_cell"]),
                _paragraph(counts["High"], styles["table_cell"]),
                _paragraph(counts["Medium"], styles["table_cell"]),
                _paragraph(counts["Low"], styles["table_cell"]),
                _paragraph(counts["Unrated"], styles["table_cell"]),
            ])
        widths = [available_width * 0.38] + [available_width * 0.62 / 6] * 6
        table = LongTable(host_data, colWidths=widths, repeatRows=1, hAlign="LEFT", splitByRow=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("GRID", (0, 0), (-1, -1), 0.35, LINE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("ALIGN", (1, 1), (-1, -1), "CENTER"),
        ]))
        story.append(table)
        if len(host_severity) > 1000:
            story.append(_paragraph(f"Showing the first 1,000 of {len(host_severity)} affected hosts.", styles["muted"]))

    story.extend(_section_heading("Open-Service Exposure Observations", styles))
    if not observations:
        story.append(_paragraph("No services were explicitly marked open in the database snapshot.", styles["muted"]))
    else:
        observation_data = [[
            _paragraph("Observation", styles["table_head"]),
            _paragraph("Host / Port", styles["table_head"]),
            _paragraph("Recorded evidence", styles["table_head"]),
            _paragraph("Suggested review", styles["table_head"]),
        ]]
        for item in observations[:1000]:
            observation_data.append([
                _safe_paragraph("title", item["title"], styles["table_cell"], 240),
                _paragraph(f"{item['host']} / {item['port']}", styles["table_cell"], already_safe=True),
                _paragraph(item["evidence"][:500], styles["table_cell"], already_safe=True),
                _paragraph(item["remediation"][:500], styles["table_cell"], already_safe=True),
            ])
        widths = [available_width * 0.25, available_width * 0.17, available_width * 0.28, available_width * 0.30]
        table = LongTable(observation_data, colWidths=widths, repeatRows=1, hAlign="LEFT", splitByRow=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("GRID", (0, 0), (-1, -1), 0.35, LINE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(table)
        if len(observations) > 1000:
            story.append(_paragraph(f"Showing the first 1,000 of {len(observations)} open-service observations.", styles["muted"]))

    for key, title, _columns in SECTIONS:
        story.extend(_section_heading(title, styles))
        story.extend(_inventory_table(key, records.get(key, []), available_width, styles))

    limitations = (
        "Scope and limitations: this document reflects records returned by the active Metasploit database workspace at generation time. "
        "It does not run new scans, verify exploitability, validate service versions, or prove absence of vulnerabilities. "
        "Severity uses the explicit database severity/risk field when recognized; otherwise, available CVSS-like scores are placed into CVSS v3-style bands for triage only. "
        "Unrated items need manual review. Database remediation text is shown when provided; otherwise, generic validation guidance is displayed."
    )
    story.extend(_section_heading("Scope and Limitations", styles))
    story.append(_paragraph(limitations, styles["notice"]))
    story.append(Spacer(1, 8))
    story.append(_paragraph("Generated by MSF Web Console. Handle this report as sensitive assessment data.", styles["muted"]))

    def canvas_factory(*args: Any, **kwargs: Any) -> canvas.Canvas:
        kwargs["pageCompression"] = 0
        return canvas.Canvas(*args, **kwargs)

    document.build(story, onFirstPage=_page_decor, onLaterPages=_page_decor, canvasmaker=canvas_factory)
    return output.getvalue()
