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
            CREATE TABLE IF NOT EXISTS execution_record_metadata (
                record_id TEXT PRIMARY KEY,
                execution_id INTEGER NOT NULL REFERENCES tool_executions(id) ON DELETE CASCADE,
                assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
                review_state TEXT NOT NULL DEFAULT 'active'
                    CHECK (review_state IN ('active', 'dismissed')),
                reviewed_at TEXT,
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_execution_record_metadata_assessment
                ON execution_record_metadata(assessment_id, review_state, reviewed_at);
            """
        )


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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

    target = _asset_url(target_url)
    if target:
        candidates.add(("url", target[0], target[1]))

    for record in records:
        if not isinstance(record, dict) or record.get("resource_type") == "malformed" or record.get("kind") == "redirect_chain":
            continue
        for key in ("url", "target", "final_url"):
            value = record.get(key)
            if isinstance(value, str) and value:
                candidate = _asset_url(value)
                if candidate:
                    candidates.add(("url", candidate[0], candidate[1]))
        host_value = record.get("host")
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
            state = "in_scope" if hostname in approved_hosts else "out_of_scope"
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
            item.setdefault("_record_id", uuid.uuid4().hex)
            stored_records.append(item)
        _store_discovered_assets(
            connection, scope["assessment_id"], tool_id, target_url, stored_records, finished_at
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
                "SELECT review_state, reviewed_at, notes FROM execution_record_metadata WHERE record_id = ? AND execution_id = ?",
                (record_id, execution_id),
            ).fetchone()
            item["record_id"] = record_id
            item["review_state"] = metadata["review_state"] if metadata else "active"
            item["reviewed_at"] = metadata["reviewed_at"] if metadata else None
            item["notes"] = metadata["notes"] if metadata else ""
            enriched.append(item)
        result["records"] = enriched
    return result

def _rebuild_assessment_assets(connection: sqlite3.Connection, assessment_id: int) -> None:
    """Rebuild inventory from retained execution evidence after a record deletion."""
    connection.execute("DELETE FROM assessment_assets WHERE assessment_id = ?", (assessment_id,))
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
            "SELECT review_state, reviewed_at, notes FROM execution_record_metadata WHERE record_id = ?",
            (record_id,),
        ).fetchone()
        state = request.review_state if "review_state" in changes else (existing["review_state"] if existing else "active")
        reviewed_at = (
            now if request.reviewed else None
        ) if "reviewed" in changes else (existing["reviewed_at"] if existing else None)
        notes = request.notes if "notes" in changes else (existing["notes"] if existing else "")
        connection.execute(
            """
            INSERT INTO execution_record_metadata
                (record_id, execution_id, assessment_id, review_state, reviewed_at, notes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(record_id) DO UPDATE SET
                review_state = excluded.review_state,
                reviewed_at = excluded.reviewed_at,
                notes = excluded.notes,
                updated_at = excluded.updated_at
            """,
            (record_id, execution_id, assessment_id, state, reviewed_at, notes or "", now, now),
        )
    return {
        "record_id": record_id, "review_state": state,
        "reviewed_at": reviewed_at, "notes": notes or "",
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
