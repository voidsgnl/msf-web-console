from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from typing import Any


SECTIONS = [
    ("hosts", "Hosts", ("address", "host", "name", "mac", "os_name", "os_flavor", "purpose", "info")),
    ("services", "Services", ("host", "port", "proto", "name", "state", "info")),
    ("vulns", "Vulnerability Records", ("host", "port", "name", "info", "refs")),
    ("creds", "Credential Inventory (secret values omitted)", ("host", "port", "service_name", "user", "username", "realm", "type", "private_type")),
    ("loot", "Loot & Evidence", ("host", "service", "name", "ltype", "ctype", "info", "created_at", "has_data", "size")),
]

SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Informational", "Unrated")
SEVERITY_POINTS = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1, "Informational": 0, "Unrated": 0}
FREEFORM_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization)\s*[:=]\s*([^\s,;]+)"
)
UNIX_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9])/(?:home|tmp|root|var|opt|etc|srv|mnt|run|usr|private|Users)/[^\s<>),;]+"
)
WINDOWS_PATH_RE = re.compile(r"(?i)\b[A-Z]:\\(?:[^\\\s]+\\)*[^\\\s]+")
SENSITIVE_KEY_PARTS = (
    "password", "passwd", "secret", "token", "private_data", "private_value",
    "private_key", "hash", "path", "download_id", "session_key",
)


def _safe_value(key: str, value: Any) -> str:
    lowered = key.lower()
    if (lowered != "has_data" and any(part in lowered for part in SENSITIVE_KEY_PARTS)):
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
    text = str(value)
    text = FREEFORM_SECRET_RE.sub(lambda match: f"{match.group(1)}=[redacted]", text)
    text = UNIX_PATH_RE.sub("[path omitted]", text)
    text = WINDOWS_PATH_RE.sub("[path omitted]", text)
    return text[:1200]


def _cell(key: str, value: Any) -> str:
    return html.escape(_safe_value(key, value), quote=True)


def _first_value(record: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        value = record.get(key)
        if value not in (None, ""):
            return value
    return None


def _severity(record: dict[str, Any]) -> tuple[str, str]:
    """Use recorded severity first, then CVSS-like scores when present."""
    raw = _first_value(record, ("severity", "risk", "risk_level", "criticality"))
    if raw is not None:
        lowered = str(raw).strip().lower()
        if any(word in lowered for word in ("critical", "urgent", "emergency")):
            return "Critical", f"Metasploit field: {raw}"
        if any(word in lowered for word in ("high", "severe")):
            return "High", f"Metasploit field: {raw}"
        if any(word in lowered for word in ("medium", "moderate", "medium risk")):
            return "Medium", f"Metasploit field: {raw}"
        if any(word in lowered for word in ("low", "minor")):
            return "Low", f"Metasploit field: {raw}"
        if any(word in lowered for word in ("info", "none", "informational")):
            return "Informational", f"Metasploit field: {raw}"

    for key in ("cvss_score", "cvss_v3", "cvss", "score"):
        value = record.get(key)
        if value in (None, ""):
            continue
        match = re.search(r"(?<!\d)(10(?:\.0+)?|[0-9](?:\.\d+)?)", str(value))
        if not match:
            continue
        score = float(match.group(1))
        # CVSS v3-style bands are shown as an interpretation, not a re-calculation.
        if score >= 9.0:
            return "Critical", f"{key}={score:g} (CVSS v3-style band)"
        if score >= 7.0:
            return "High", f"{key}={score:g} (CVSS v3-style band)"
        if score >= 4.0:
            return "Medium", f"{key}={score:g} (CVSS v3-style band)"
        if score > 0:
            return "Low", f"{key}={score:g} (CVSS v3-style band)"
        return "Informational", f"{key}={score:g}"
    return "Unrated", "No explicit severity or usable score in the database record"


def _remediation(record: dict[str, Any]) -> str:
    recorded = _first_value(record, ("remediation", "solution", "recommendation", "fix", "mitigation"))
    if recorded is not None:
        return _safe_value("remediation", recorded)
    return (
        "Validate the finding and affected version, consult the vendor advisory, "
        "apply the vendor-supported fix or mitigation, then retest. The database "
        "record did not include a specific remediation."
    )


def _vulnerability_findings(vulns: list[dict[str, Any]]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for index, record in enumerate(vulns, start=1):
        severity, source = _severity(record)
        title = _first_value(record, ("name", "title", "vulnerability", "refs")) or f"Vulnerability record {index}"
        host = _first_value(record, ("host", "address", "host_address", "rhost")) or "Unknown host"
        port = _first_value(record, ("port", "service_port"))
        evidence = _first_value(record, ("info", "description", "details"))
        cvss = _first_value(record, ("cvss_score", "cvss_v3", "cvss", "score"))
        findings.append({
            "title": _safe_value("title", title),
            "host": _safe_value("host", host),
            "port": str(port) if port not in (None, "") else "—",
            "severity": severity,
            "severity_source": _safe_value("severity_source", source),
            "score": _safe_value("cvss_score", cvss) if cvss not in (None, "") else "—",
            "evidence": _safe_value("evidence", evidence) if evidence not in (None, "") else "No additional evidence was included in the database record.",
            "remediation": _remediation(record),
        })
    return findings


def _exposure_observations(services: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Summarize services explicitly marked open; these are not vulnerability findings."""
    observations: list[dict[str, str]] = []
    for record in services:
        state = str(record.get("state") or "").strip().lower()
        if state != "open":
            continue
        host = _first_value(record, ("host", "address", "host_address")) or "Unknown host"
        port = _first_value(record, ("port", "service_port")) or "Unknown port"
        proto = _first_value(record, ("proto", "protocol")) or "tcp"
        name = _first_value(record, ("name", "service_name")) or "Unidentified service"
        observations.append({
            "title": _safe_value("title", f"{name} exposed on {proto}/{port}"),
            "host": _safe_value("host", host),
            "port": _safe_value("port", f"{proto}/{port}"),
            "evidence": _safe_value("evidence", _first_value(record, ("info", "banner", "version")) or f"Database state: {state}"),
            "remediation": (
                "Confirm this service is required and reachable only from intended networks. "
                "Review authentication and encryption, keep the service patched, and restrict "
                "access with host/network controls where practical. Exposure alone does not prove a vulnerability."
            ),
        })
    return observations


def _findings_html(findings: list[dict[str, str]]) -> str:
    if not findings:
        return (
            '<p class="empty">No vulnerability records were present in this workspace snapshot. '
            'This does not prove the environment is free of vulnerabilities.</p>'
        )
    rows = []
    for item in findings[:1000]:
        rows.append(
            "<tr>"
            f"<td><strong>{html.escape(item['title'], quote=True)}</strong>"
            f'<div class="subtle">Severity source: {html.escape(item["severity_source"], quote=True)}</div></td>'
            f"<td><span class=\"severity severity-{item['severity'].lower()}\">{html.escape(item['severity'])}</span></td>"
            f"<td>{html.escape(item['host'], quote=True)}</td>"
            f"<td>{html.escape(item['port'], quote=True)}</td>"
            f"<td>{html.escape(item['score'], quote=True)}</td>"
            f"<td>{html.escape(item['evidence'][:900], quote=True)}</td>"
            f"<td>{html.escape(item['remediation'][:900], quote=True)}</td>"
            "</tr>"
        )
    note = f'<p class="muted">Showing first 1,000 of {len(findings)} vulnerability records.</p>' if len(findings) > 1000 else ""
    return (
        '<div class="table-wrap"><table><thead><tr><th>Finding</th><th>Severity</th>'
        '<th>Host</th><th>Port</th><th>Score</th><th>Recorded evidence</th><th>Recommended action</th></tr></thead>'
        f"<tbody>{''.join(rows[:1000])}</tbody></table></div>{note}"
    )


def _observations_html(observations: list[dict[str, str]]) -> str:
    if not observations:
        return '<p class="empty">No services were explicitly marked open in the database snapshot.</p>'
    rows = []
    for item in observations[:1000]:
        rows.append(
            "<tr>"
            f"<td>{html.escape(item['title'], quote=True)}</td>"
            f"<td>{html.escape(item['host'], quote=True)}</td>"
            f"<td>{html.escape(item['port'], quote=True)}</td>"
            f"<td>{html.escape(item['evidence'][:700], quote=True)}</td>"
            f"<td>{html.escape(item['remediation'], quote=True)}</td>"
            "</tr>"
        )
    return (
        '<p class="muted">These are attack-surface observations based on service state, not confirmed vulnerabilities.</p>'
        '<div class="table-wrap"><table><thead><tr><th>Observation</th><th>Host</th><th>Protocol / Port</th>'
        '<th>Recorded evidence</th><th>Suggested review</th></tr></thead>'
        f"<tbody>{''.join(rows[:1000])}</tbody></table></div>"
    )


def build_assessment_report(workspace: str, records: dict[str, list[dict[str, Any]]]) -> str:
    """Build a self-contained HTML assessment report with explicit risk provenance."""
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    workspace_text = html.escape(_safe_value("workspace", workspace or "default"), quote=True)
    hosts = records.get("hosts", [])
    services = records.get("services", [])
    vulns = records.get("vulns", [])
    creds = records.get("creds", [])
    loot = records.get("loot", [])

    findings = _vulnerability_findings(vulns)
    observations = _exposure_observations(services)
    severity_counts = {level: sum(item["severity"] == level for item in findings) for level in SEVERITY_ORDER}
    rated_count = sum(severity_counts[level] for level in SEVERITY_ORDER if level != "Unrated")
    priority_points = sum(SEVERITY_POINTS[item["severity"]] for item in findings)
    summary_sentences = []
    if findings:
        record_word = "record" if len(findings) == 1 else "records"
        summary_sentences.append(
            f"The workspace contains {len(findings)} vulnerability {record_word}: "
            + ", ".join(f"{severity_counts[level]} {level.lower()}" for level in SEVERITY_ORDER if severity_counts[level])
            + "."
        )
        if severity_counts["Unrated"]:
            summary_sentences.append(
                f"{severity_counts['Unrated']} record(s) have no explicit severity or usable score and require manual triage."
            )
    else:
        summary_sentences.append(
            "No vulnerability records were present in the database snapshot; this is not evidence that no vulnerabilities exist."
        )
    if observations:
        service_word = "service was" if len(observations) == 1 else "services were"
        summary_sentences.append(
            f"{len(observations)} {service_word} explicitly marked open. Review exposure and access controls; open state alone is not a vulnerability."
        )
    else:
        summary_sentences.append("No service records were explicitly marked open in this snapshot.")
    summary = " ".join(summary_sentences)

    cards_data = [
        ("Hosts", len(hosts)),
        ("Services", len(services)),
        ("Vulnerability records", len(vulns)),
        ("Open-service observations", len(observations)),
        ("Credential records", len(creds)),
        ("Loot records", len(loot)),
    ]
    cards = "".join(
        f'<article class="metric"><div class="metric-label">{html.escape(title)}</div>'
        f'<div class="metric-value">{count}</div></article>'
        for title, count in cards_data
    )
    severity_cards = "".join(
        f'<article class="severity-card"><div class="metric-label">{level}</div>'
        f'<div class="metric-value">{severity_counts[level]}</div></article>'
        for level in SEVERITY_ORDER
    )

    sections_html: list[str] = []
    for key, title, columns in SECTIONS:
        rows = records.get(key, [])
        visible = [row for row in rows if isinstance(row, dict)][:1000]
        if visible:
            header_html = "".join(f"<th>{html.escape(column.replace('_', ' ').title())}</th>" for column in columns)
            body_html = "".join(
                "<tr>" + "".join(f"<td>{_cell(column, row.get(column))}</td>" for column in columns) + "</tr>"
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

    limitations = (
        "Scope and limitations: this document reflects records returned by the active Metasploit database workspace at generation time. "
        "It does not run new scans, verify exploitability, validate service versions, or prove absence of vulnerabilities. "
        "Severity uses the explicit database severity/risk field when recognized; otherwise, available CVSS-like scores are placed into CVSS v3-style bands for triage only. "
        "Unrated items need manual review. Remediation text from the database is shown when provided; otherwise, generic validation guidance is displayed."
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Metasploit Assessment — {workspace_text}</title>
<style>
:root {{ color-scheme:light; --ink:#172033; --muted:#64748b; --line:#dbe2ea; --panel:#f3f6fa; --accent:#2563eb; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:#eef2f7; color:var(--ink); font:14px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif; }}
main {{ max-width:1240px; margin:0 auto; padding:36px 24px 60px; }}
header {{ background:#fff; border:1px solid var(--line); border-radius:14px; padding:28px; }}
.eyebrow {{ color:var(--accent); text-transform:uppercase; letter-spacing:.12em; font-size:11px; font-weight:700; }}
h1 {{ margin:8px 0; font-size:30px; letter-spacing:-.03em; }}
h2 {{ margin:0 0 14px; font-size:18px; }}
h3 {{ margin:18px 0 10px; font-size:14px; }}
.meta,.muted,.subtle {{ color:var(--muted); font-size:12px; }}
.metrics {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(135px,1fr)); gap:12px; margin:18px 0; }}
.metric,.severity-card {{ background:#fff; border:1px solid var(--line); border-radius:10px; padding:14px; }}
.metric-label {{ color:var(--muted); font-size:10px; text-transform:uppercase; letter-spacing:.06em; }}
.metric-value {{ font-size:26px; font-weight:750; }}
.summary,.priority-panel {{ margin:18px 0 26px; padding:20px; border:1px solid var(--line); border-radius:12px; background:#fff; }}
.summary p {{ margin:0; }}
.severity-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(115px,1fr)); gap:10px; }}
.severity-critical {{ color:#991b1b; background:#fee2e2; }} .severity-high {{ color:#9a3412; background:#ffedd5; }}
.severity-medium {{ color:#854d0e; background:#fef3c7; }} .severity-low {{ color:#166534; background:#dcfce7; }}
.severity-informational {{ color:#1d4ed8; background:#dbeafe; }} .severity-unrated {{ color:#475569; background:#e2e8f0; }}
.severity {{ display:inline-block; border-radius:99px; padding:3px 8px; font-size:11px; font-weight:700; white-space:nowrap; }}
section {{ margin:24px 0; background:#fff; border:1px solid var(--line); border-radius:12px; padding:20px; page-break-inside:avoid; }}
.section-heading {{ display:flex; justify-content:space-between; align-items:center; gap:12px; }}
.count {{ padding:2px 9px; border-radius:99px; background:var(--panel); color:var(--muted); font-size:12px; }}
.table-wrap {{ overflow-x:auto; }}
table {{ width:100%; border-collapse:collapse; font-size:12px; }}
th {{ background:var(--panel); text-align:left; font-weight:700; color:#475569; }}
th,td {{ border-bottom:1px solid var(--line); padding:9px 10px; text-align:left; vertical-align:top; overflow-wrap:anywhere; }}
tbody tr:last-child td {{ border-bottom:0; }}
.empty {{ color:var(--muted); font-size:12px; }}
footer {{ margin-top:28px; padding:16px 4px; color:var(--muted); font-size:11px; }}
@media print {{ body {{ background:#fff; }} main {{ max-width:none; padding:0; }} header,section,.metric,.severity-card,.summary,.priority-panel {{ border-color:#bbb; break-inside:avoid; }} section {{ page-break-inside:auto; }} .table-wrap {{ overflow:visible; }} th {{ print-color-adjust:exact; -webkit-print-color-adjust:exact; }} }}
</style>
</head>
<body><main>
<header>
<div class="eyebrow">MSF Web Console · Assessment Report</div>
<h1>Executive Summary</h1>
<div><strong>Workspace:</strong> {workspace_text}</div>
<div class="meta">Generated {html.escape(generated)} · Read-only snapshot of the active Metasploit database workspace</div>
<div class="summary"><p>{html.escape(summary, quote=True)}</p></div>
<p class="meta">{html.escape(limitations, quote=True)}</p>
</header>
<h2 style="margin-top:26px">Workspace Inventory</h2>
<div class="metrics">{cards}</div>
<div class="priority-panel">
<h2>Severity Summary</h2>
<div class="severity-grid">{severity_cards}</div>
<p class="meta">Severity totals cover vulnerability records only. Priority points ({priority_points}) are a simple triage aid, not a CVSS score or quantified likelihood. {rated_count} of {len(findings)} finding(s) have a recognized rating.</p>
</div>
<section>
<div class="section-heading"><h2>Prioritized Vulnerability Findings</h2><span class="count">{len(findings)}</span></div>
{_findings_html(findings)}
</section>
<section>
<div class="section-heading"><h2>Open-Service Exposure Observations</h2><span class="count">{len(observations)}</span></div>
{_observations_html(observations)}
</section>
{''.join(sections_html)}
<footer>Generated by MSF Web Console. Handle this report as sensitive assessment data.</footer>
</main></body></html>
"""
