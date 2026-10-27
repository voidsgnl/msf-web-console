from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Any


SECTIONS = [
    ("hosts", "Hosts", ("address", "host", "name", "mac", "os_name", "os_flavor", "purpose", "info")),
    ("services", "Services", ("host", "port", "proto", "name", "state", "info")),
    ("vulns", "Vulnerabilities", ("host", "port", "name", "info", "refs")),
    ("creds", "Credentials (secrets omitted)", ("host", "port", "service_name", "user", "username", "realm", "type", "private_type")),
    ("loot", "Loot & Evidence", ("host", "service", "name", "ltype", "ctype", "info", "created_at", "has_data", "size")),
]

SENSITIVE_KEY_PARTS = (
    "password", "passwd", "secret", "token", "private_data", "private_value",
    "private_key", "hash", "data", "path", "download_id", "session_key",
)


def _safe_value(key: str, value: Any) -> str:
    lowered = key.lower()
    if any(part in lowered for part in SENSITIVE_KEY_PARTS):
        return "[redacted]" if value not in (None, "") else "—"
    if value is None or value == "":
        return "—"
    if isinstance(value, (bytes, bytearray)):
        return "[binary content omitted]"
    if isinstance(value, (dict, list, tuple)):
        try:
            value = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
        except (TypeError, ValueError):
            value = str(value)
    return str(value)[:1200]


def _cell(key: str, value: Any) -> str:
    return html.escape(_safe_value(key, value), quote=True)


def build_assessment_report(workspace: str, records: dict[str, list[dict[str, Any]]]) -> str:
    """Build a self-contained HTML report; secret values and server paths are omitted."""
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    workspace_text = html.escape(workspace or "default", quote=True)

    cards = "".join(
        f'<article class="metric"><div class="metric-label">{html.escape(title)}</div>'
        f'<div class="metric-value">{len(records.get(key, []))}</div></article>'
        for key, title, _ in SECTIONS
    )

    sections_html: list[str] = []
    for key, title, columns in SECTIONS:
        rows = records.get(key, [])
        visible = [
            row for row in rows
            if isinstance(row, dict)
        ][:1000]
        if visible:
            header_html = "".join(f"<th>{html.escape(column.replace('_', ' ').title())}</th>" for column in columns)
            body_html = "".join(
                "<tr>" + "".join(
                    f"<td>{_cell(column, row.get(column))}</td>" for column in columns
                ) + "</tr>"
                for row in visible
            )
            truncated_note = (
                f'<p class="muted">Showing first 1,000 of {len(rows)} records.</p>'
                if len(rows) > len(visible) else ""
            )
            table_html = (
                f'<div class="table-wrap"><table><thead><tr>{header_html}</tr></thead>'
                f'<tbody>{body_html}</tbody></table></div>{truncated_note}'
            )
        else:
            table_html = '<p class="empty">No records in this workspace.</p>'

        sections_html.append(
            f'<section><div class="section-heading"><h2>{html.escape(title)}</h2>'
            f'<span class="count">{len(rows)}</span></div>{table_html}</section>'
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Metasploit Assessment — {workspace_text}</title>
<style>
:root {{ color-scheme: light; --ink:#172033; --muted:#64748b; --line:#dbe2ea; --panel:#f3f6fa; --accent:#2563eb; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:#eef2f7; color:var(--ink); font:14px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif; }}
main {{ max-width:1200px; margin:0 auto; padding:36px 24px 60px; }}
header {{ background:#fff; border:1px solid var(--line); border-radius:14px; padding:28px; }}
.eyebrow {{ color:var(--accent); text-transform:uppercase; letter-spacing:.12em; font-size:11px; font-weight:700; }}
h1 {{ margin:8px 0; font-size:30px; letter-spacing:-.03em; }}
.meta {{ color:var(--muted); font-size:12px; }}
.metrics {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:12px; margin:18px 0 30px; }}
.metric {{ background:#fff; border:1px solid var(--line); border-radius:10px; padding:16px; }}
.metric-label {{ color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.06em; }}
.metric-value {{ font-size:28px; font-weight:700; }}
section {{ margin:24px 0; background:#fff; border:1px solid var(--line); border-radius:12px; padding:20px; page-break-inside:avoid; }}
.section-heading {{ display:flex; justify-content:space-between; align-items:center; gap:12px; }}
h2 {{ margin:0 0 14px; font-size:18px; }}
.count {{ padding:2px 9px; border-radius:99px; background:var(--panel); color:var(--muted); font-size:12px; }}
.table-wrap {{ overflow-x:auto; }}
table {{ width:100%; border-collapse:collapse; font-size:12px; }}
th {{ background:var(--panel); text-align:left; font-weight:700; color:#475569; }}
th,td {{ border-bottom:1px solid var(--line); padding:9px 10px; text-align:left; vertical-align:top; overflow-wrap:anywhere; }}
tbody tr:last-child td {{ border-bottom:0; }}
.empty,.muted {{ color:var(--muted); font-size:12px; }}
footer {{ margin-top:28px; padding:16px 4px; color:var(--muted); font-size:11px; }}
@media print {{ body {{ background:#fff; }} main {{ max-width:none; padding:0; }} header,section,.metric {{ border-color:#bbb; break-inside:avoid; }} section {{ page-break-inside:auto; }} .table-wrap {{ overflow:visible; }} th {{ print-color-adjust:exact; -webkit-print-color-adjust:exact; }} }}
</style>
</head>
<body><main>
<header>
<div class="eyebrow">MSF Web Console · Assessment Report</div>
<h1>Workspace Assessment</h1>
<div><strong>Workspace:</strong> {workspace_text}</div>
<div class="meta">Generated {html.escape(generated)} · Read-only snapshot of the active Metasploit database workspace</div>
<p class="meta">Credential secret fields, artifact bytes, download references and server filesystem paths are omitted. This report is a database snapshot, not a guarantee that every discovered service or finding is current.</p>
</header>
<div class="metrics">{cards}</div>
{''.join(sections_html)}
<footer>Generated by MSF Web Console. Handle this report as sensitive assessment data.</footer>
</main></body></html>
"""
