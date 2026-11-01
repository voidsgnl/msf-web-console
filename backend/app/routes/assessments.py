"""Platform-owned assessment and target-scope persistence.

Uses Python's built-in SQLite driver so the platform data store is independent
of Metasploit's database and requires no additional service or dependency.
"""
import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.routes.web_recon import _normalise_url

router = APIRouter(prefix="/api/assessments", tags=["assessments"])


def _database_path() -> Path:
    configured = os.getenv("ASSESSMENT_DATABASE_PATH")
    if configured:
        return Path(configured).expanduser()
    return Path(__file__).resolve().parents[2] / "data" / "assessments.sqlite3"


def _connect() -> sqlite3.Connection:
    path = _database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def _connection():
    connection = _connect()
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def _initialise() -> None:
    with _connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'completed', 'archived')),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS assessment_targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
                url TEXT NOT NULL,
                hostname TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE (assessment_id, url)
            );
            CREATE INDEX IF NOT EXISTS idx_assessment_targets_assessment
                ON assessment_targets(assessment_id);
            CREATE TABLE IF NOT EXISTS tool_executions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
                target_id INTEGER NOT NULL REFERENCES assessment_targets(id) ON DELETE CASCADE,
                tool_id TEXT NOT NULL,
                target_url TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                exit_code INTEGER NOT NULL,
                output_truncated INTEGER NOT NULL DEFAULT 0,
                result_json TEXT NOT NULL,
                stderr TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_tool_executions_assessment
                ON tool_executions(assessment_id, id DESC);
            CREATE TABLE IF NOT EXISTS execution_jobs (
                id TEXT PRIMARY KEY,
                assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
                tool_id TEXT NOT NULL,
                target_url TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'completed', 'failed', 'cancelled', 'interrupted')),
                created_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                execution_id INTEGER REFERENCES tool_executions(id) ON DELETE SET NULL,
                error TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_execution_jobs_assessment
                ON execution_jobs(assessment_id, created_at DESC);
            CREATE TABLE IF NOT EXISTS assessment_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
                asset_type TEXT NOT NULL CHECK (asset_type IN ('url', 'host')),
                value TEXT NOT NULL,
                hostname TEXT NOT NULL,
                scope_state TEXT NOT NULL CHECK (scope_state IN ('in_scope', 'out_of_scope')),
                source_tool TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                UNIQUE (assessment_id, asset_type, value)
            );
            CREATE INDEX IF NOT EXISTS idx_assessment_assets_assessment
                ON assessment_assets(assessment_id, scope_state, asset_type);
            CREATE TABLE IF NOT EXISTS assessment_services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
                hostname TEXT NOT NULL,
                port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
                protocol TEXT NOT NULL CHECK (protocol = 'tcp'),
                service TEXT NOT NULL DEFAULT '',
                product TEXT NOT NULL DEFAULT '',
                version TEXT NOT NULL DEFAULT '',
                scope_state TEXT NOT NULL CHECK (scope_state IN ('in_scope', 'out_of_scope')),
                source_tool TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                UNIQUE (assessment_id, hostname, port, protocol)
            );
            CREATE INDEX IF NOT EXISTS idx_assessment_services_assessment
                ON assessment_services(assessment_id, scope_state, hostname, port);
            CREATE TABLE IF NOT EXISTS execution_record_metadata (
                record_id TEXT PRIMARY KEY,
                execution_id INTEGER NOT NULL REFERENCES tool_executions(id) ON DELETE CASCADE,
                assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
                review_state TEXT NOT NULL DEFAULT 'active'
                    CHECK (review_state IN ('active', 'dismissed')),
                reviewed_at TEXT,
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                record_type TEXT NOT NULL DEFAULT 'evidence' CHECK (record_type IN ('evidence', 'finding'))
            );
            CREATE INDEX IF NOT EXISTS idx_execution_record_metadata_assessment
                ON execution_record_metadata(assessment_id, review_state, reviewed_at);
            """
        )
        columns = {row['name'] for row in connection.execute('PRAGMA table_info(execution_record_metadata)').fetchall()}
        if 'record_type' not in columns:
            connection.execute("ALTER TABLE execution_record_metadata ADD COLUMN record_type TEXT NOT NULL DEFAULT 'evidence' CHECK (record_type IN ('evidence', 'finding'))")


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _normalise_evidence_envelope(
    tool_id: str, target_url: str, observed_at: str, record: dict
) -> dict:
    """Add a stable, non-verdict evidence envelope while preserving tool fields."""
    item = dict(record)
    explicit_type = str(item.get("evidence_type") or "").strip().lower()
    if explicit_type:
        observation_type = explicit_type
    elif tool_id == "nmap" or item.get("port") is not None:
        observation_type = "open_service"
    elif tool_id in {"amass", "subfinder"} or item.get("host"):
        observation_type = "discovered_host"
    elif tool_id == "nuclei":
        observation_type = "scanner_match"
    elif tool_id == "testssl.sh":
        observation_type = "tls_observation"
    elif tool_id == "wpscan":
        observation_type = "cms_observation"
    elif tool_id == "nikto":
        observation_type = "web_server_observation"
    elif tool_id == "katana":
        observation_type = "endpoint_observation"
    elif tool_id in {"gobuster", "ffuf", "feroxbuster", "manual-path-check"}:
        observation_type = "content_discovery"
    elif tool_id in {"httpx", "whatweb"}:
        observation_type = "service_fingerprint"
    else:
        observation_type = "tool_observation"

    severity = str(item.get("severity") or "unknown").strip().lower()
    if severity not in {"critical", "high", "medium", "low", "info", "informational", "unknown"}:
        severity = "unknown"

    summary_value = (
        item.get("summary") or item.get("finding") or item.get("title")
        or item.get("service") or item.get("host") or item.get("url")
        or item.get("target") or target_url
    )
    summary = " ".join(str(summary_value).split())[:1000]

    item["evidence_schema_version"] = 1
    item["source_tool"] = tool_id
    item["target_url"] = target_url
    item["observed_at"] = observed_at
    item["observation_type"] = observation_type
    item["summary"] = summary
    item["severity"] = severity
    # These are deliberately neutral defaults. Scanner output is not a
    # verified vulnerability, and the platform must not infer confidence.
    item["confidence"] = "unassessed"
    item["verification_state"] = "unverified"
    return item


class AssessmentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=2000)


class AssessmentStatusUpdate(BaseModel):
    status: str = Field(pattern=r"^(active|completed|archived)$")


class TargetCreate(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    authorized: bool = False


class ExecutionRecordUpdate(BaseModel):
    review_state: str | None = Field(default=None, pattern=r"^(active|dismissed)$")
    reviewed: bool | None = None
    notes: str | None = Field(default=None, max_length=4000)
    record_type: str | None = Field(default=None, pattern=r"^(evidence|finding)$")


def _assessment_or_404(connection: sqlite3.Connection, assessment_id: int) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM assessments WHERE id = ?", (assessment_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(404, "Assessment not found.")
    return row


@router.get("")
def list_assessments():
    _initialise()
    with _connection() as connection:
        rows = connection.execute(
            """
            SELECT a.*,
                (SELECT COUNT(*) FROM assessment_targets t
                 WHERE t.assessment_id = a.id) AS target_count
            FROM assessments a
            ORDER BY a.updated_at DESC, a.id DESC
            """
        ).fetchall()
    return {"assessments": [dict(row) for row in rows]}


@router.post("", status_code=201)
def create_assessment(request: AssessmentCreate):
    _initialise()
    name = request.name.strip()
    if not name:
        raise HTTPException(400, "Assessment name cannot be blank.")
    now = _timestamp()
    with _connection() as connection:
        cursor = connection.execute(
            "INSERT INTO assessments (name, description, created_at, updated_at) VALUES (?, ?, ?, ?)",
            (name, request.description.strip(), now, now),
        )
        row = connection.execute(
            "SELECT * FROM assessments WHERE id = ?", (cursor.lastrowid,)
        ).fetchone()
    return dict(row)


@router.get("/{assessment_id}")
def get_assessment(assessment_id: int):
    _initialise()
    with _connection() as connection:
        assessment = _assessment_or_404(connection, assessment_id)
        targets = connection.execute(
            "SELECT id, url, hostname, created_at FROM assessment_targets WHERE assessment_id = ? ORDER BY id",
            (assessment_id,),
        ).fetchall()
    return {**dict(assessment), "targets": [dict(row) for row in targets]}


@router.patch("/{assessment_id}")
def update_assessment_status(assessment_id: int, request: AssessmentStatusUpdate):
    _initialise()
    with _connection() as connection:
        _assessment_or_404(connection, assessment_id)
        connection.execute(
            "UPDATE assessments SET status = ?, updated_at = ? WHERE id = ?",
            (request.status, _timestamp(), assessment_id),
        )
        row = _assessment_or_404(connection, assessment_id)
    return dict(row)


@router.post("/{assessment_id}/targets", status_code=201)
def add_assessment_target(assessment_id: int, request: TargetCreate):
    if not request.authorized:
        raise HTTPException(
            400,
            "Confirm that you own this target or have explicit permission to assess it.",
        )
    target_url = _normalise_url(request.url)
    parsed = urlsplit(target_url)
    hostname = (parsed.hostname or "").lower()
    _initialise()
    with _connection() as connection:
        assessment = _assessment_or_404(connection, assessment_id)
        if assessment["status"] != "active":
            raise HTTPException(409, "Targets can only be added to an active assessment.")
        try:
            cursor = connection.execute(
                "INSERT INTO assessment_targets (assessment_id, url, hostname, created_at) VALUES (?, ?, ?, ?)",
                (assessment_id, target_url.rstrip("/"), hostname, _timestamp()),
            )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(409, "This target is already in the assessment scope.") from exc
        row = connection.execute(
            "SELECT id, url, hostname, created_at FROM assessment_targets WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
        connection.execute(
            "UPDATE assessments SET updated_at = ? WHERE id = ?",
            (_timestamp(), assessment_id),
        )
    return dict(row)


@router.delete("/{assessment_id}/targets/{target_id}", status_code=204)
def remove_assessment_target(assessment_id: int, target_id: int):
    _initialise()
    with _connection() as connection:
        _assessment_or_404(connection, assessment_id)
        cursor = connection.execute(
            "DELETE FROM assessment_targets WHERE id = ? AND assessment_id = ?",
            (target_id, assessment_id),
        )
        if cursor.rowcount == 0:
            raise HTTPException(404, "Target not found in this assessment.")
        connection.execute(
            "UPDATE assessments SET updated_at = ? WHERE id = ?",
            (_timestamp(), assessment_id),
        )


def create_execution_job(assessment_id: int, tool_id: str, target_url: str) -> dict:
    _initialise()
    job_id = uuid.uuid4().hex
    now = _timestamp()
    with _connection() as connection:
        _assessment_or_404(connection, assessment_id)
        connection.execute(
            "INSERT INTO execution_jobs (id, assessment_id, tool_id, target_url, state, created_at) VALUES (?, ?, ?, ?, 'queued', ?)",
            (job_id, assessment_id, tool_id, target_url, now),
        )
    return {"id": job_id, "assessment_id": assessment_id, "tool_id": tool_id, "target_url": target_url, "state": "queued", "created_at": now}


def update_execution_job(job_id: str, state: str, *, execution_id: int | None = None, error: str = "") -> dict | None:
    _initialise()
    if state not in {"queued", "running", "completed", "failed", "cancelled", "interrupted"}:
        raise ValueError("Invalid execution job state.")
    now = _timestamp()
    with _connection() as connection:
        row = connection.execute("SELECT * FROM execution_jobs WHERE id = ?", (job_id,)).fetchone()
        if row is None:
            return None
        started_at = row["started_at"] or (now if state == "running" else None)
        finished_at = now if state in {"completed", "failed", "cancelled", "interrupted"} else None
        connection.execute(
            "UPDATE execution_jobs SET state = ?, started_at = ?, finished_at = ?, execution_id = COALESCE(?, execution_id), error = ? WHERE id = ?",
            (state, started_at, finished_at, execution_id, error[:1000], job_id),
        )
        updated = connection.execute("SELECT * FROM execution_jobs WHERE id = ?", (job_id,)).fetchone()
    return dict(updated) if updated else None


def recover_stale_execution_jobs() -> int:
    """Mark queued or running jobs interrupted after a backend restart."""
    _initialise()
    with _connection() as connection:
        cursor = connection.execute(
            "UPDATE execution_jobs SET state = 'interrupted', finished_at = ?, error = ? WHERE state IN ('queued', 'running')",
            (_timestamp(), "Backend restarted before the job completed."),
        )
        return cursor.rowcount


def get_execution_job(assessment_id: int, job_id: str) -> dict:
    _initialise()
    with _connection() as connection:
        _assessment_or_404(connection, assessment_id)
        row = connection.execute(
            "SELECT * FROM execution_jobs WHERE id = ? AND assessment_id = ?",
            (job_id, assessment_id),
        ).fetchone()
    if row is None:
        raise HTTPException(404, "Execution job not found in this assessment.")
    return dict(row)


def list_execution_jobs(assessment_id: int) -> dict:
    _initialise()
    with _connection() as connection:
        _assessment_or_404(connection, assessment_id)
        rows = connection.execute(
            "SELECT * FROM execution_jobs WHERE assessment_id = ? ORDER BY created_at DESC LIMIT 100",
            (assessment_id,),
        ).fetchall()
    return {"jobs": [dict(row) for row in rows]}


def request_execution_job_cancel(assessment_id: int, job_id: str) -> dict:
    job = get_execution_job(assessment_id, job_id)
    if job["state"] in {"completed", "failed", "cancelled", "interrupted"}:
        raise HTTPException(409, "This execution job is already finished.")
    from app.routes.web_recon import request_job_cancellation
    if not request_job_cancellation(job_id):
        raise HTTPException(409, "The execution job is not currently cancellable.")
    return {"id": job_id, "state": "cancelling"}


def assert_target_in_scope(assessment_id: int, target_url: str) -> dict:
    """Require an exact approved origin before an adapter can execute."""
    _initialise()
    parsed = urlsplit(_normalise_url(target_url))
    hostname = (parsed.hostname or "").lower()
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    origin = (parsed.scheme.lower(), hostname, port)
    with _connection() as connection:
        assessment = _assessment_or_404(connection, assessment_id)
        if assessment["status"] != "active":
            raise HTTPException(409, "The assessment is not active.")
        rows = connection.execute(
            "SELECT id, url FROM assessment_targets WHERE assessment_id = ?",
            (assessment_id,),
        ).fetchall()
    for row in rows:
        approved = urlsplit(row["url"])
        approved_port = approved.port or (443 if approved.scheme == "https" else 80)
        if origin == (approved.scheme.lower(), (approved.hostname or "").lower(), approved_port):
            return {"assessment_id": assessment_id, "target_id": row["id"], "approved_url": row["url"]}
    raise HTTPException(403, "Target is outside this assessment's approved scope.")



def _approved_origins(connection: sqlite3.Connection, assessment_id: int) -> set[tuple[str, str, int]]:
    rows = connection.execute(
        "SELECT url FROM assessment_targets WHERE assessment_id = ?", (assessment_id,)
    ).fetchall()
    origins = set()
    for row in rows:
        parsed = urlsplit(row["url"])
        origins.add((
            parsed.scheme.lower(),
            (parsed.hostname or "").lower(),
            parsed.port or (443 if parsed.scheme.lower() == "https" else 80),
        ))
    return origins


def _asset_url(raw: str) -> tuple[str, str] | None:
    try:
        normalized = _normalise_url(raw)
        parsed = urlsplit(normalized)
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return None
        return normalized.rstrip("/"), hostname
    except (HTTPException, ValueError):
        return None


def _store_discovered_assets(
    connection: sqlite3.Connection,
    assessment_id: int,
    tool_id: str,
    target_url: str,
    records: list[dict],
    seen_at: str,
) -> None:
    origins = _approved_origins(connection, assessment_id)
    candidates: set[tuple[str, str, str]] = set()
    nmap_hosts_in_scope: set[str] = set()

    target = _asset_url(target_url)
    if target:
        candidates.add(("url", target[0], target[1]))

    for record in records:
        if not isinstance(record, dict) or record.get("resource_type") == "malformed" or record.get("kind") == "redirect_chain":
            continue
        # Manual path checks are analyst-supplied probes, not discovery results.
        # Keep their full observations in execution evidence, but do not promote
        # every tested path into the asset inventory before it is reviewed.
        if tool_id != "manual-path-check":
            for key in ("url", "target", "final_url"):
                value = record.get(key)
                if isinstance(value, str) and value:
                    candidate = _asset_url(value)
                    if candidate:
                        candidates.add(("url", candidate[0], candidate[1]))
        host_value = record.get("host")
        if tool_id == "nmap" and isinstance(host_value, str):
            aliases = record.get("hostnames") if isinstance(record.get("hostnames"), list) else []
            if any(str(alias).lower().rstrip(".") in {host for _, host, _ in origins} for alias in aliases):
                nmap_hosts_in_scope.add(host_value.strip().lower().rstrip("."))
        if isinstance(host_value, str) and host_value.strip():
            host = host_value.strip().lower().rstrip(".")
            if "://" in host_value or "/" in host_value:
                parsed_candidate = _asset_url(host_value)
                host = parsed_candidate[1] if parsed_candidate else ""
            if host and len(host) <= 253 and not any(ch.isspace() for ch in host):
                candidates.add(("host", host, host))

    approved_hosts = {host for _, host, _ in origins}
    for asset_type, value, hostname in candidates:
        if asset_type == "url":
            parsed = urlsplit(value)
            port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
            state = "in_scope" if (parsed.scheme.lower(), hostname, port) in origins else "out_of_scope"
        else:
            state = "in_scope" if hostname in approved_hosts or hostname in nmap_hosts_in_scope else "out_of_scope"
        connection.execute(
            """
            INSERT INTO assessment_assets
                (assessment_id, asset_type, value, hostname, scope_state,
                 source_tool, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(assessment_id, asset_type, value) DO UPDATE SET
                last_seen = excluded.last_seen,
                source_tool = excluded.source_tool,
                scope_state = excluded.scope_state
            """,
            (assessment_id, asset_type, value, hostname, state, tool_id, seen_at, seen_at),
        )


def _store_discovered_services(
    connection: sqlite3.Connection,
    assessment_id: int,
    tool_id: str,
    records: list[dict],
    seen_at: str,
) -> None:
    """Persist only explicit open TCP service observations from Nmap evidence."""
    if tool_id != "nmap":
        return
    approved_hosts = {
        host for _, host, _ in _approved_origins(connection, assessment_id)
    }
    nmap_hosts_in_scope = {
        str(record.get("host") or "").strip().lower().rstrip(".")
        for record in records
        if isinstance(record, dict)
        and isinstance(record.get("hostnames"), list)
        and any(str(alias).lower().rstrip(".") in approved_hosts for alias in record["hostnames"])
    }
    for record in records:
        if not isinstance(record, dict):
            continue
        if str(record.get("state") or "").lower() != "open":
            continue
        if str(record.get("protocol") or "tcp").lower() != "tcp":
            continue
        try:
            port = int(record.get("port"))
        except (TypeError, ValueError):
            continue
        if not 1 <= port <= 65535:
            continue
        host = str(record.get("host") or "").strip().lower().rstrip(".")
        if not host or len(host) > 253 or any(ch.isspace() for ch in host):
            continue
        state = "in_scope" if host in approved_hosts or host in nmap_hosts_in_scope else "out_of_scope"
        connection.execute(
            """
            INSERT INTO assessment_services
                (assessment_id, hostname, port, protocol, service, product, version,
                 scope_state, source_tool, first_seen, last_seen)
            VALUES (?, ?, ?, 'tcp', ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(assessment_id, hostname, port, protocol) DO UPDATE SET
                service = excluded.service,
                product = excluded.product,
                version = excluded.version,
                scope_state = excluded.scope_state,
                source_tool = excluded.source_tool,
                last_seen = excluded.last_seen
            """,
            (
                assessment_id, host, port,
                str(record.get("service") or "")[:120],
                str(record.get("product") or "")[:160],
                str(record.get("version") or "")[:120],
                state, tool_id, seen_at, seen_at,
            ),
        )


def record_tool_execution(
    scope: dict,
    tool_id: str,
    target_url: str,
    started_at: str,
    finished_at: str,
    exit_code: int,
    output_truncated: bool,
    records: list[dict],
    stderr: str,
) -> dict:
    _initialise()
    with _connection() as connection:
        stored_records = []
        for record in records:
            item = dict(record) if isinstance(record, dict) else {"raw": str(record)}
            item = _normalise_evidence_envelope(tool_id, target_url, finished_at, item)
            item.setdefault("_record_id", uuid.uuid4().hex)
            stored_records.append(item)
        _store_discovered_assets(
            connection, scope["assessment_id"], tool_id, target_url, stored_records, finished_at
        )
        _store_discovered_services(
            connection, scope["assessment_id"], tool_id, stored_records, finished_at
        )
        cursor = connection.execute(
            """
            INSERT INTO tool_executions
                (assessment_id, target_id, tool_id, target_url, started_at,
                 finished_at, exit_code, output_truncated, result_json, stderr)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scope["assessment_id"], scope["target_id"], tool_id, target_url,
                started_at, finished_at, exit_code, int(output_truncated),
                json.dumps(stored_records, ensure_ascii=False), stderr[:4000],
            ),
        )
        row = connection.execute(
            """
            SELECT id, assessment_id, target_id, tool_id, target_url,
                   started_at, finished_at, exit_code, output_truncated
            FROM tool_executions WHERE id = ?
            """,
            (cursor.lastrowid,),
        ).fetchone()
    return dict(row)



@router.get("/{assessment_id}/assets")
def list_assessment_assets(assessment_id: int):
    _initialise()
    with _connection() as connection:
        _assessment_or_404(connection, assessment_id)
        # Inventory is derived from retained evidence. Rebuilding also removes
        # legacy manual-path-check URLs that older versions promoted blindly.
        _rebuild_assessment_assets(connection, assessment_id)
        rows = connection.execute(
            """
            SELECT id, assessment_id, asset_type, value, hostname, scope_state,
                   source_tool, first_seen, last_seen
            FROM assessment_assets
            WHERE assessment_id = ?
            ORDER BY CASE scope_state WHEN 'in_scope' THEN 0 ELSE 1 END,
                     asset_type, value
            """,
            (assessment_id,),
        ).fetchall()
    assets = [dict(row) for row in rows]
    return {
        "assets": assets,
        "counts": {
            "total": len(assets),
            "in_scope": sum(item["scope_state"] == "in_scope" for item in assets),
            "out_of_scope": sum(item["scope_state"] == "out_of_scope" for item in assets),
        },
    }


@router.get("/{assessment_id}/services")
def list_assessment_services(assessment_id: int):
    _initialise()
    with _connection() as connection:
        _assessment_or_404(connection, assessment_id)
        _rebuild_assessment_assets(connection, assessment_id)
        rows = connection.execute(
            """
            SELECT id, assessment_id, hostname, port, protocol, service, product,
                   version, scope_state, source_tool, first_seen, last_seen
            FROM assessment_services
            WHERE assessment_id = ?
            ORDER BY CASE scope_state WHEN 'in_scope' THEN 0 ELSE 1 END,
                     hostname, port
            """,
            (assessment_id,),
        ).fetchall()
    services = [dict(row) for row in rows]
    return {
        "services": services,
        "counts": {
            "total": len(services),
            "in_scope": sum(item["scope_state"] == "in_scope" for item in services),
            "out_of_scope": sum(item["scope_state"] == "out_of_scope" for item in services),
        },
    }


@router.get("/{assessment_id}/executions")
def list_assessment_executions(assessment_id: int):
    _initialise()
    with _connection() as connection:
        _assessment_or_404(connection, assessment_id)
        rows = connection.execute(
            """
            SELECT id, assessment_id, target_id, tool_id, target_url,
                   started_at, finished_at, exit_code, output_truncated
            FROM tool_executions
            WHERE assessment_id = ?
            ORDER BY id DESC LIMIT 100
            """,
            (assessment_id,),
        ).fetchall()
    return {"executions": [dict(row) for row in rows]}

@router.get("/{assessment_id}/execution-jobs")
def list_assessment_execution_jobs(assessment_id: int):
    return list_execution_jobs(assessment_id)


@router.get("/{assessment_id}/execution-jobs/{job_id}")
def get_assessment_execution_job(assessment_id: int, job_id: str):
    return get_execution_job(assessment_id, job_id)


@router.post("/{assessment_id}/execution-jobs/{job_id}/cancel")
def cancel_assessment_execution_job(assessment_id: int, job_id: str):
    return request_execution_job_cancel(assessment_id, job_id)


@router.get("/{assessment_id}/executions/{execution_id}")
def get_assessment_execution(assessment_id: int, execution_id: int):
    _initialise()
    with _connection() as connection:
        _assessment_or_404(connection, assessment_id)
        row = connection.execute(
            """
            SELECT id, assessment_id, target_id, tool_id, target_url,
                   started_at, finished_at, exit_code, output_truncated,
                   result_json, stderr
            FROM tool_executions WHERE id = ? AND assessment_id = ?
            """,
            (execution_id, assessment_id),
        ).fetchone()
        if row is None:
            raise HTTPException(404, "Execution not found in this assessment.")
        result = dict(row)
        result["output_truncated"] = bool(result["output_truncated"])
        records = json.loads(result.pop("result_json"))
        enriched = []
        for index, record in enumerate(records):
            item = dict(record) if isinstance(record, dict) else {"raw": str(record)}
            record_id = item.get("_record_id") or f"legacy-{execution_id}-{index}"
            metadata = connection.execute(
                "SELECT review_state, reviewed_at, notes, record_type FROM execution_record_metadata WHERE record_id = ? AND execution_id = ?",
                (record_id, execution_id),
            ).fetchone()
            item["record_id"] = record_id
            item["review_state"] = metadata["review_state"] if metadata else "active"
            item["reviewed_at"] = metadata["reviewed_at"] if metadata else None
            item["notes"] = metadata["notes"] if metadata else ""
            item["record_type"] = metadata["record_type"] if metadata else "evidence"
            enriched.append(item)
        result["records"] = enriched
    return result

def _rebuild_assessment_assets(connection: sqlite3.Connection, assessment_id: int) -> None:
    """Rebuild inventory from retained execution evidence after a record deletion."""
    connection.execute("DELETE FROM assessment_assets WHERE assessment_id = ?", (assessment_id,))
    connection.execute("DELETE FROM assessment_services WHERE assessment_id = ?", (assessment_id,))
    executions = connection.execute(
        "SELECT tool_id, target_url, finished_at, result_json FROM tool_executions WHERE assessment_id = ? ORDER BY id",
        (assessment_id,),
    ).fetchall()
    for execution in executions:
        try:
            records = json.loads(execution["result_json"])
        except (TypeError, ValueError):
            records = []
        _store_discovered_assets(
            connection, assessment_id, execution["tool_id"], execution["target_url"],
            records if isinstance(records, list) else [], execution["finished_at"],
        )
        _store_discovered_services(
            connection, assessment_id, execution["tool_id"],
            records if isinstance(records, list) else [], execution["finished_at"],
        )


@router.patch("/{assessment_id}/executions/{execution_id}/records/{record_id}")
def update_execution_record(
    assessment_id: int, execution_id: int, record_id: str, request: ExecutionRecordUpdate
):
    _initialise()
    changes = request.model_fields_set
    if not changes:
        raise HTTPException(400, "Provide at least one record field to update.")
    if "review_state" in changes and request.review_state is None:
        raise HTTPException(400, "Review state cannot be null.")
    if "reviewed" in changes and request.reviewed is None:
        raise HTTPException(400, "Reviewed state cannot be null.")
    if "record_type" in changes and request.record_type is None:
        raise HTTPException(400, "Record type cannot be null.")
    with _connection() as connection:
        _assessment_or_404(connection, assessment_id)
        row = connection.execute(
            "SELECT result_json FROM tool_executions WHERE id = ? AND assessment_id = ?",
            (execution_id, assessment_id),
        ).fetchone()
        if row is None:
            raise HTTPException(404, "Execution not found in this assessment.")
        records = json.loads(row["result_json"])
        record = next(
            (item for index, item in enumerate(records)
             if (item.get("_record_id") or f"legacy-{execution_id}-{index}") == record_id),
            None,
        )
        if record is None:
            raise HTTPException(404, "Record not found in this execution.")
        if not record.get("_record_id"):
            record["_record_id"] = record_id
            connection.execute(
                "UPDATE tool_executions SET result_json = ? WHERE id = ? AND assessment_id = ?",
                (json.dumps(records, ensure_ascii=False), execution_id, assessment_id),
            )
        now = _timestamp()
        existing = connection.execute(
            "SELECT review_state, reviewed_at, notes, record_type FROM execution_record_metadata WHERE record_id = ?",
            (record_id,),
        ).fetchone()
        state = request.review_state if "review_state" in changes else (existing["review_state"] if existing else "active")
        reviewed_at = (
            now if request.reviewed else None
        ) if "reviewed" in changes else (existing["reviewed_at"] if existing else None)
        notes = request.notes if "notes" in changes else (existing["notes"] if existing else "")
        record_type = request.record_type if "record_type" in changes else (existing["record_type"] if existing else "evidence")
        connection.execute(
            """
            INSERT INTO execution_record_metadata
                (record_id, execution_id, assessment_id, review_state, reviewed_at, notes, created_at, updated_at, record_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(record_id) DO UPDATE SET
                review_state = excluded.review_state,
                reviewed_at = excluded.reviewed_at,
                notes = excluded.notes,
                record_type = excluded.record_type,
                updated_at = excluded.updated_at
            """,
            (record_id, execution_id, assessment_id, state, reviewed_at, notes or "", now, now, record_type),
        )
    return {
        "record_id": record_id, "review_state": state,
        "reviewed_at": reviewed_at, "notes": notes or "", "record_type": record_type,
    }


@router.delete("/{assessment_id}/executions/{execution_id}/records/{record_id}")
def delete_execution_record(assessment_id: int, execution_id: int, record_id: str):
    """Permanently remove one stored evidence record, retaining the execution history."""
    _initialise()
    with _connection() as connection:
        _assessment_or_404(connection, assessment_id)
        row = connection.execute(
            "SELECT result_json FROM tool_executions WHERE id = ? AND assessment_id = ?",
            (execution_id, assessment_id),
        ).fetchone()
        if row is None:
            raise HTTPException(404, "Execution not found in this assessment.")
        records = json.loads(row["result_json"])
        for index, item in enumerate(records):
            if not item.get("_record_id"):
                item["_record_id"] = f"legacy-{execution_id}-{index}"
        retained = [item for item in records if item.get("_record_id") != record_id]
        if len(retained) == len(records):
            raise HTTPException(404, "Record not found in this execution.")
        connection.execute(
            "UPDATE tool_executions SET result_json = ? WHERE id = ? AND assessment_id = ?",
            (json.dumps(retained, ensure_ascii=False), execution_id, assessment_id),
        )
        connection.execute(
            "DELETE FROM execution_record_metadata WHERE record_id = ?", (record_id,)
        )
        _rebuild_assessment_assets(connection, assessment_id)
    return {"deleted": True, "record_id": record_id}


def _all_assessment_records(connection: sqlite3.Connection, assessment_id: int) -> list[dict]:
    executions = connection.execute(
        "SELECT id, tool_id, target_url, started_at, finished_at, exit_code, result_json FROM tool_executions WHERE assessment_id = ? ORDER BY id DESC",
        (assessment_id,),
    ).fetchall()
    output = []
    for execution in executions:
        records = json.loads(execution["result_json"])
        for index, raw in enumerate(records):
            item = dict(raw) if isinstance(raw, dict) else {"raw": str(raw)}
            record_id = item.get("_record_id") or f"legacy-{execution['id']}-{index}"
            if not item.get("_record_id"):
                item["_record_id"] = record_id
            meta = connection.execute(
                "SELECT review_state, reviewed_at, notes, record_type FROM execution_record_metadata WHERE record_id = ?",
                (record_id,),
            ).fetchone()
            item.update({
                "record_id": record_id, "execution_id": execution["id"],
                "tool_id": execution["tool_id"], "target_url": execution["target_url"],
                "started_at": execution["started_at"], "finished_at": execution["finished_at"],
                "exit_code": execution["exit_code"],
                "review_state": meta["review_state"] if meta else "active",
                "reviewed_at": meta["reviewed_at"] if meta else None,
                "notes": meta["notes"] if meta else "",
                "record_type": meta["record_type"] if meta else "evidence",
            })
            output.append(item)
    return output


@router.get("/{assessment_id}/records")
def list_assessment_records(assessment_id: int, q: str = "", tool_id: str = "", record_type: str = "", review_state: str = "", reviewed: str = "", sort_by: str = "newest"):
    _initialise()
    with _connection() as connection:
        _assessment_or_404(connection, assessment_id)
        records = _all_assessment_records(connection, assessment_id)
    query = q.strip().casefold()
    if query:
        records = [item for item in records if query in json.dumps(item, ensure_ascii=False, default=str).casefold()]
    if tool_id:
        records = [item for item in records if item["tool_id"] == tool_id]
    if record_type in {"evidence", "finding"}:
        records = [item for item in records if item["record_type"] == record_type]
    if review_state in {"active", "dismissed"}:
        records = [item for item in records if item["review_state"] == review_state]
    if reviewed == "yes":
        records = [item for item in records if item["reviewed_at"]]
    elif reviewed == "no":
        records = [item for item in records if not item["reviewed_at"]]
    if sort_by == "oldest":
        records.sort(key=lambda item: item["started_at"])
    elif sort_by == "tool":
        records.sort(key=lambda item: (item["tool_id"], item["started_at"]), reverse=True)
    elif sort_by == "target":
        records.sort(key=lambda item: (item["target_url"], item["started_at"]), reverse=True)
    else:
        records.sort(key=lambda item: item["started_at"], reverse=True)
    return {"records": records, "total": len(records)}


@router.patch("/{assessment_id}/records/bulk")
def bulk_update_assessment_records(assessment_id: int, request: dict):
    ids = request.get("record_ids")
    if not isinstance(ids, list) or not ids or len(ids) > 200 or not all(isinstance(value, str) for value in ids):
        raise HTTPException(400, "Select between 1 and 200 evidence records.")
    fields = {key for key in ("review_state", "reviewed", "record_type") if key in request}
    if not fields:
        raise HTTPException(400, "Provide a review state, reviewed flag, or record type.")
    if "review_state" in request and request["review_state"] not in ("active", "dismissed"):
        raise HTTPException(400, "Invalid review state.")
    if "record_type" in request and request["record_type"] not in ("evidence", "finding"):
        raise HTTPException(400, "Invalid record type.")
    if "reviewed" in request and not isinstance(request["reviewed"], bool):
        raise HTTPException(400, "Reviewed state must be a boolean.")
    now = _timestamp()
    with _connection() as connection:
        _assessment_or_404(connection, assessment_id)
        records = _all_assessment_records(connection, assessment_id)
        selected = [item for item in records if item["record_id"] in set(ids)]
        if len(selected) != len(set(ids)):
            raise HTTPException(404, "One or more selected records were not found.")
        for item in selected:
            state = request.get("review_state", item["review_state"])
            reviewed_at = (now if request["reviewed"] else None) if "reviewed" in request else item["reviewed_at"]
            category = request.get("record_type", item["record_type"])
            connection.execute(
                "INSERT INTO execution_record_metadata (record_id, execution_id, assessment_id, review_state, reviewed_at, notes, created_at, updated_at, record_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(record_id) DO UPDATE SET review_state=excluded.review_state, reviewed_at=excluded.reviewed_at, record_type=excluded.record_type, updated_at=excluded.updated_at",
                (item["record_id"], item["execution_id"], assessment_id, state, reviewed_at, item["notes"], now, now, category),
            )
    return {"updated": len(selected)}


@router.delete("/{assessment_id}/records/bulk")
def bulk_delete_assessment_records(assessment_id: int, request: dict):
    ids = request.get("record_ids")
    if not isinstance(ids, list) or not ids or len(ids) > 200 or not all(isinstance(value, str) for value in ids):
        raise HTTPException(400, "Select between 1 and 200 evidence records.")
    with _connection() as connection:
        _assessment_or_404(connection, assessment_id)
        records = _all_assessment_records(connection, assessment_id)
        wanted = set(ids)
        selected = [item for item in records if item["record_id"] in wanted]
        if len(selected) != len(wanted):
            raise HTTPException(404, "One or more selected records were not found.")
        grouped = {}
        for item in selected:
            grouped.setdefault(item["execution_id"], set()).add(item["record_id"])
        for execution_id, remove_ids in grouped.items():
            row = connection.execute("SELECT result_json FROM tool_executions WHERE id = ? AND assessment_id = ?", (execution_id, assessment_id)).fetchone()
            stored = json.loads(row["result_json"]) if row else []
            kept = [item for index, item in enumerate(stored) if (item.get("_record_id") or f"legacy-{execution_id}-{index}") not in remove_ids]
            connection.execute("UPDATE tool_executions SET result_json = ? WHERE id = ?", (json.dumps(kept, ensure_ascii=False), execution_id))
        connection.executemany("DELETE FROM execution_record_metadata WHERE record_id = ?", [(value,) for value in wanted])
        _rebuild_assessment_assets(connection, assessment_id)
    return {"deleted": len(selected)}


@router.get("/{assessment_id}/history")
def assessment_history_report(assessment_id: int):
    _initialise()
    with _connection() as connection:
        _assessment_or_404(connection, assessment_id)
        rows = connection.execute("SELECT tool_id, COUNT(*) AS runs, MIN(started_at) AS first_run, MAX(finished_at) AS last_run, SUM(CASE WHEN exit_code = 0 THEN 1 ELSE 0 END) AS successful_runs FROM tool_executions WHERE assessment_id = ? GROUP BY tool_id ORDER BY tool_id", (assessment_id,)).fetchall()
        records = _all_assessment_records(connection, assessment_id)
        runs = connection.execute("SELECT COUNT(*) FROM tool_executions WHERE assessment_id = ?", (assessment_id,)).fetchone()[0]
    return {"assessment_id": assessment_id, "total_runs": runs, "total_records": len(records), "findings": sum(item["record_type"] == "finding" for item in records), "evidence": sum(item["record_type"] == "evidence" for item in records), "reviewed": sum(bool(item["reviewed_at"]) for item in records), "dismissed": sum(item["review_state"] == "dismissed" for item in records), "by_tool": [dict(row) for row in rows]}


@router.get("/{assessment_id}/compare")
def compare_assessment_runs(assessment_id: int, baseline_id: int, comparison_id: int):
    if baseline_id == comparison_id:
        raise HTTPException(400, "Choose two different executions to compare.")
    _initialise()
    with _connection() as connection:
        _assessment_or_404(connection, assessment_id)
        rows = connection.execute("SELECT id, tool_id, target_url, result_json FROM tool_executions WHERE assessment_id = ? AND id IN (?, ?)", (assessment_id, baseline_id, comparison_id)).fetchall()
    if len(rows) != 2:
        raise HTTPException(404, "Both executions must belong to this assessment.")
    by_id = {row["id"]: row for row in rows}
    def keyed(row):
        output = {}
        for item in json.loads(row["result_json"]):
            # Run-specific envelope timestamps and storage IDs must not
            # make otherwise identical scanner observations appear changed.
            safe = {
                key: value for key, value in item.items()
                if key not in {"_record_id", "observed_at"}
            }
            output[json.dumps(safe, sort_keys=True, ensure_ascii=False, default=str)] = safe
        return output
    before, after = keyed(by_id[baseline_id]), keyed(by_id[comparison_id])
    return {"baseline": {"id": baseline_id, "tool_id": by_id[baseline_id]["tool_id"], "target_url": by_id[baseline_id]["target_url"]}, "comparison": {"id": comparison_id, "tool_id": by_id[comparison_id]["tool_id"], "target_url": by_id[comparison_id]["target_url"]}, "added": [after[key] for key in after.keys() - before.keys()], "removed": [before[key] for key in before.keys() - after.keys()], "unchanged": [after[key] for key in after.keys() & before.keys()]}
