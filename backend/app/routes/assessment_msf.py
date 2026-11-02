"""Explicit links between Metasploit activity and approved assessment targets.

The operator chooses the assessment target after reviewing the Metasploit
activity. The association is therefore recorded as operator-attributed, not
as an independently verified match between RPC output and target identity.
"""
import re
import sqlite3
from typing import Any, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.msf_rpc import MsfRpcError, rpc
from app.routes import assessments

router = APIRouter(prefix="/api/assessments/{assessment_id}/msf-activity", tags=["assessment-metasploit"])

RUN_UUID_RE = re.compile(r"^[A-Za-z0-9]{12,64}$")


class ActivityCreate(BaseModel):
    kind: Literal["module_run", "session"]
    reference: str = Field(min_length=1, max_length=128)
    target_id: int
    analyst_note: str = Field(default="", max_length=4000)


class ActivityReview(BaseModel):
    review_state: Literal["unreviewed", "reviewed", "dismissed"]
    analyst_note: str | None = Field(default=None, max_length=4000)


def _initialise_activity_store() -> None:
    assessments._initialise()
    with assessments._connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS assessment_msf_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
                target_id INTEGER NOT NULL REFERENCES assessment_targets(id) ON DELETE CASCADE,
                kind TEXT NOT NULL CHECK (kind IN ('module_run', 'session')),
                external_reference TEXT NOT NULL,
                external_state TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                attribution TEXT NOT NULL DEFAULT 'operator_assigned',
                review_state TEXT NOT NULL DEFAULT 'unreviewed'
                    CHECK (review_state IN ('unreviewed', 'reviewed', 'dismissed')),
                analyst_note TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE (assessment_id, kind, external_reference)
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_assessment_msf_activity "
            "ON assessment_msf_activity(assessment_id, created_at DESC)"
        )


def _safe_session_snapshot(value: dict[str, Any]) -> dict[str, Any]:
    # Deliberately exclude session datastore, credentials, routes, and console data.
    allowed = (
        "type", "tunnel_peer", "tunnel_local", "session_host", "session_port",
        "via_exploit", "via_payload", "opened_at", "platform", "arch",
    )
    return {key.strip(): value[key] for key in allowed if key in value}


def _resolve_activity(kind: str, reference: str) -> tuple[str, dict[str, Any]]:
    try:
        if kind == "module_run":
            if not RUN_UUID_RE.fullmatch(reference):
                raise HTTPException(400, "Invalid Metasploit module run UUID.")
            result = rpc.call("module.results", reference)
            if not isinstance(result, dict):
                raise HTTPException(502, "Metasploit returned an unexpected module result.")
            state = str(result.get("status") or "unknown").lower()[:40]
            raw_result = result.get("result")
            summary = {
                "status": state,
                "job_id": result.get("job_id"),
                "result_type": type(raw_result).__name__ if raw_result is not None else None,
                "result_keys": sorted(str(key) for key in raw_result.keys())[:40]
                    if isinstance(raw_result, dict) else [],
            }
            return state, summary

        if not reference.isdigit() or len(reference) > 8:
            raise HTTPException(400, "Session reference must be a numeric Metasploit session ID.")
        sessions = rpc.call("session.list")
        info = sessions.get(int(reference)) or sessions.get(reference) if isinstance(sessions, dict) else None
        if not isinstance(info, dict):
            raise HTTPException(404, "Metasploit session was not found. Refresh the session list.")
        return "active", _safe_session_snapshot(info)
    except HTTPException:
        raise
    except MsfRpcError as exc:
        raise HTTPException(502, f"Could not verify Metasploit activity: {exc}") from exc


@router.get("")
def list_linked_msf_activity(assessment_id: int):
    _initialise_activity_store()
    with assessments._connection() as connection:
        assessments._assessment_or_404(connection, assessment_id)
        rows = connection.execute(
            """
            SELECT a.*, t.url AS approved_target_url, t.hostname AS approved_target_hostname
            FROM assessment_msf_activity a
            JOIN assessment_targets t ON t.id = a.target_id
            WHERE a.assessment_id = ?
            ORDER BY a.created_at DESC, a.id DESC
            """,
            (assessment_id,),
        ).fetchall()
    import json
    return {
        "activity": [
            {**dict(row), "snapshot": json.loads(row["snapshot_json"])}
            for row in rows
        ],
        "notice": (
            "Target attribution is the operator's explicit association. Metasploit "
            "module results and session metadata are not independent proof of target "
            "identity, vulnerability, exploitation success, or remediation."
        ),
    }


@router.post("", status_code=201)
def link_msf_activity(assessment_id: int, request: ActivityCreate):
    _initialise_activity_store()
    with assessments._connection() as connection:
        assessment = assessments._assessment_or_404(connection, assessment_id)
        if assessment["status"] == "archived":
            raise HTTPException(409, "Activity cannot be linked to an archived assessment.")
        target = connection.execute(
            "SELECT id FROM assessment_targets WHERE id = ? AND assessment_id = ?",
            (request.target_id, assessment_id),
        ).fetchone()
        if target is None:
            raise HTTPException(400, "Choose a target already approved in this assessment.")
    state, snapshot = _resolve_activity(request.kind, request.reference.strip())
    now = assessments._timestamp()
    import json
    try:
        with assessments._connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO assessment_msf_activity
                    (assessment_id, target_id, kind, external_reference, external_state,
                     snapshot_json, analyst_note, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    assessment_id, request.target_id, request.kind,
                    request.reference.strip(), state,
                    json.dumps(snapshot, ensure_ascii=False, default=str),
                    request.analyst_note.strip(), now, now,
                ),
            )
            row = connection.execute(
                "SELECT * FROM assessment_msf_activity WHERE id = ?",
                (cursor.lastrowid,),
            ).fetchone()
    except sqlite3.IntegrityError as exc:
        raise HTTPException(409, "This Metasploit activity is already linked to the assessment.") from exc
    return {**dict(row), "snapshot": snapshot, "attribution": "operator_assigned"}


@router.patch("/{activity_id}")
def review_linked_msf_activity(
    assessment_id: int, activity_id: int, request: ActivityReview
):
    _initialise_activity_store()
    now = assessments._timestamp()
    with assessments._connection() as connection:
        assessments._assessment_or_404(connection, assessment_id)
        row = connection.execute(
            "SELECT * FROM assessment_msf_activity WHERE id = ? AND assessment_id = ?",
            (activity_id, assessment_id),
        ).fetchone()
        if row is None:
            raise HTTPException(404, "Linked Metasploit activity not found.")
        note = row["analyst_note"] if request.analyst_note is None else request.analyst_note.strip()
        connection.execute(
            """
            UPDATE assessment_msf_activity
            SET review_state = ?, analyst_note = ?, updated_at = ?
            WHERE id = ? AND assessment_id = ?
            """,
            (request.review_state, note, now, activity_id, assessment_id),
        )
        updated = connection.execute(
            "SELECT * FROM assessment_msf_activity WHERE id = ?",
            (activity_id,),
        ).fetchone()
    import json
    return {**dict(updated), "snapshot": json.loads(updated["snapshot_json"])}
