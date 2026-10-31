"""Platform-owned assessment and target-scope persistence.

Uses Python's built-in SQLite driver so the platform data store is independent
of Metasploit's database and requires no additional service or dependency.
"""
import os
import sqlite3
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


def _initialise() -> None:
    with _connect() as connection:
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
    with _connect() as connection:
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
    with _connect() as connection:
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
    with _connect() as connection:
        assessment = _assessment_or_404(connection, assessment_id)
        targets = connection.execute(
            "SELECT id, url, hostname, created_at FROM assessment_targets WHERE assessment_id = ? ORDER BY id",
            (assessment_id,),
        ).fetchall()
    return {**dict(assessment), "targets": [dict(row) for row in targets]}


@router.patch("/{assessment_id}")
def update_assessment_status(assessment_id: int, request: AssessmentStatusUpdate):
    _initialise()
    with _connect() as connection:
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
    with _connect() as connection:
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
    with _connect() as connection:
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
    with _connect() as connection:
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
