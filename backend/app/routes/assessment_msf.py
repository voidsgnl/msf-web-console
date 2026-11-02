"""Explicit links between Metasploit activity and approved assessment targets.

The operator chooses the assessment target after reviewing the Metasploit
activity. The association is therefore recorded as operator-attributed, not
as an independently verified match between RPC output and target identity.
"""
import hashlib
import re
import sqlite3
from typing import Any, Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.msf_rpc import MsfRpcError, rpc
from app.routes import assessments, db as msf_db

router = APIRouter(prefix="/api/assessments/{assessment_id}/msf-activity", tags=["assessment-metasploit"])

RUN_UUID_RE = re.compile(r"^[A-Za-z0-9-]{12,64}$")
LOOT_REFERENCE_RE = re.compile(r"^(\d{1,3})\.([a-f0-9]{64})$")


class ActivityCreate(BaseModel):
    kind: Literal["module_run", "session"]
    reference: str = Field(min_length=1, max_length=128)
    target_id: int
    analyst_note: str = Field(default="", max_length=4000)


class ActivityReview(BaseModel):
    review_state: Literal["unreviewed", "reviewed", "dismissed"]
    analyst_note: str | None = Field(default=None, max_length=4000)


class LootLinkCreate(BaseModel):
    download_id: str = Field(min_length=1, max_length=100)
    target_id: int
    analyst_note: str = Field(default="", max_length=4000)


class LootLinkReview(BaseModel):
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
            """
            CREATE TABLE IF NOT EXISTS assessment_msf_loot (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
                target_id INTEGER NOT NULL REFERENCES assessment_targets(id) ON DELETE CASCADE,
                external_reference TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                artifact_sha256 TEXT,
                artifact_size INTEGER,
                review_state TEXT NOT NULL DEFAULT 'unreviewed'
                    CHECK (review_state IN ('unreviewed', 'reviewed', 'dismissed')),
                analyst_note TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE (assessment_id, external_reference)
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_assessment_msf_loot "
            "ON assessment_msf_loot(assessment_id, created_at DESC)"
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



def _resolve_loot_reference(download_id: str) -> tuple[dict[str, Any], str | None, int | None]:
    """Resolve an opaque loot download reference without accepting filesystem paths."""
    match = LOOT_REFERENCE_RE.fullmatch(download_id)
    if not match:
        raise HTTPException(400, "Invalid Metasploit loot reference. Refresh the loot list.")
    offset = int(match.group(1))
    if offset >= 100:
        raise HTTPException(400, "Invalid Metasploit loot offset. Refresh the loot list.")
    try:
        result = rpc.call("db.loots", {"limit": 1, "offset": offset})
    except MsfRpcError as exc:
        raise HTTPException(502, f"Could not verify Metasploit loot: {exc}") from exc
    records = result.get("loots", []) if isinstance(result, dict) else []
    selected = records[0] if records and isinstance(records[0], dict) else None
    if selected is None or msf_db._loot_fingerprint(selected) != match.group(2):
        raise HTTPException(404, "Metasploit loot changed or was not found. Refresh the loot list.")
    payload = msf_db._loot_payload(selected)
    artifact_sha256 = hashlib.sha256(payload).hexdigest() if payload is not None else None
    allowed = ("name", "ltype", "ctype", "host", "service", "created_at", "updated_at")
    snapshot = {key: selected.get(key) for key in allowed if selected.get(key) is not None}
    snapshot["has_data"] = payload is not None
    snapshot["download_id"] = download_id
    return snapshot, artifact_sha256, len(payload) if payload is not None else None


@router.get("/loot")
def list_linked_msf_loot(assessment_id: int):
    _initialise_activity_store()
    with assessments._connection() as connection:
        assessments._assessment_or_404(connection, assessment_id)
        rows = connection.execute(
            """
            SELECT l.*, t.url AS approved_target_url, t.hostname AS approved_target_hostname
            FROM assessment_msf_loot l
            JOIN assessment_targets t ON t.id = l.target_id
            WHERE l.assessment_id = ?
            ORDER BY l.created_at DESC, l.id DESC
            """,
            (assessment_id,),
        ).fetchall()
    import json
    return {
        "loot": [{**dict(row), "snapshot": json.loads(row["snapshot_json"])} for row in rows],
        "notice": (
            "Loot is linked by explicit operator attribution. SHA-256 is calculated "
            "from bytes available to the backend at link time; it does not establish "
            "origin, authenticity, or that the artifact proves exploitation."
        ),
    }


@router.post("/loot", status_code=201)
def link_msf_loot(assessment_id: int, request: LootLinkCreate):
    _initialise_activity_store()
    with assessments._connection() as connection:
        assessment = assessments._assessment_or_404(connection, assessment_id)
        if assessment["status"] == "archived":
            raise HTTPException(409, "Loot cannot be linked to an archived assessment.")
        target = connection.execute(
            "SELECT id FROM assessment_targets WHERE id = ? AND assessment_id = ?",
            (request.target_id, assessment_id),
        ).fetchone()
        if target is None:
            raise HTTPException(400, "Choose a target already approved in this assessment.")
    snapshot, digest, size = _resolve_loot_reference(request.download_id.strip())
    now = assessments._timestamp()
    import json
    try:
        with assessments._connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO assessment_msf_loot
                    (assessment_id, target_id, external_reference, snapshot_json,
                     artifact_sha256, artifact_size, analyst_note, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    assessment_id, request.target_id, request.download_id.strip(),
                    json.dumps(snapshot, ensure_ascii=False, default=str),
                    digest, size, request.analyst_note.strip(), now, now,
                ),
            )
            row = connection.execute(
                "SELECT * FROM assessment_msf_loot WHERE id = ?", (cursor.lastrowid,)
            ).fetchone()
    except sqlite3.IntegrityError as exc:
        raise HTTPException(409, "This Metasploit loot item is already linked to the assessment.") from exc
    return {**dict(row), "snapshot": snapshot}


@router.patch("/loot/{loot_id}")
def review_linked_msf_loot(assessment_id: int, loot_id: int, request: LootLinkReview):
    _initialise_activity_store()
    now = assessments._timestamp()
    with assessments._connection() as connection:
        assessments._assessment_or_404(connection, assessment_id)
        row = connection.execute(
            "SELECT * FROM assessment_msf_loot WHERE id = ? AND assessment_id = ?",
            (loot_id, assessment_id),
        ).fetchone()
        if row is None:
            raise HTTPException(404, "Linked Metasploit loot item not found.")
        note = row["analyst_note"] if request.analyst_note is None else request.analyst_note.strip()
        connection.execute(
            """
            UPDATE assessment_msf_loot
            SET review_state = ?, analyst_note = ?, updated_at = ?
            WHERE id = ? AND assessment_id = ?
            """,
            (request.review_state, note, now, loot_id, assessment_id),
        )
        updated = connection.execute(
            "SELECT * FROM assessment_msf_loot WHERE id = ?", (loot_id,)
        ).fetchone()
    import json
    return {**dict(updated), "snapshot": json.loads(updated["snapshot_json"])}


recommendation_router = APIRouter(
    prefix="/api/assessments/{assessment_id}/findings",
    tags=["assessment-metasploit"],
)


def _origin_key(value: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return parsed.scheme.lower(), parsed.hostname.lower().rstrip("."), port
    except ValueError:
        return None


@recommendation_router.get("/{finding_id}/metasploit-recommendations")
def recommend_msf_modules_for_finding(assessment_id: int, finding_id: str):
    """Return CVE-reference-matched exploit modules for a validated in-scope finding.

    This is a recommendation-only hand-off. It never checks or executes a module.
    """
    with assessments._connection() as connection:
        assessment = assessments._assessment_or_404(connection, assessment_id)
        if assessment["status"] == "archived":
            raise HTTPException(409, "Archived assessments cannot create Metasploit hand-offs.")

    inventory = assessments.list_correlated_findings(assessment_id)
    finding = next((item for item in inventory["findings"] if item["id"] == finding_id), None)
    if finding is None:
        raise HTTPException(404, "Correlated finding not found.")
    if finding.get("finding_status") != "validated":
        raise HTTPException(409, "Only analyst-validated findings can be handed to Metasploit.")
    if finding.get("scope_state") != "in_scope":
        raise HTTPException(409, "The finding is not classified as in scope.")
    cve_ids = {
        str(value).upper() for value in finding.get("cve_ids", [])
        if re.fullmatch(r"(?i)CVE-\d{4}-\d{4,}", str(value))
    }
    if not cve_ids:
        raise HTTPException(422, "This finding has no CVE references to match against Metasploit module metadata.")

    finding_origin = _origin_key(str(finding.get("target") or ""))
    if finding_origin is None:
        raise HTTPException(409, "The finding does not have a valid HTTP(S) target origin.")
    with assessments._connection() as connection:
        targets = connection.execute(
            "SELECT id, url, hostname FROM assessment_targets WHERE assessment_id = ? ORDER BY id",
            (assessment_id,),
        ).fetchall()
    approved = next((row for row in targets if _origin_key(row["url"]) == finding_origin), None)
    if approved is None:
        raise HTTPException(409, "No already-approved assessment target matches the finding's exact origin.")

    from app.routes import modules

    parsed_target = urlsplit(str(finding.get("target") or ""))
    port = parsed_target.port or (443 if parsed_target.scheme == "https" else 80)
    recommendations: dict[tuple[str, str], dict[str, Any]] = {}
    contexts = [
        item for item in finding.get("software_context", [])
        if item.get("scope_state") == "in_scope" and str(item.get("product") or "").strip()
    ][:5]
    for context in contexts:
        product = str(context.get("product") or "").strip()[:120]
        version = str(context.get("version") or "").strip()[:80]
        result = modules.suggest_modules(service_info=f"{product} {version}".strip(), port=port, types="exploit")
        for candidate in result.get("candidates", []):
            if candidate.get("type") != "exploit":
                continue
            shared = sorted(cve_ids & {str(value).upper() for value in candidate.get("cve_matches", [])})
            if not shared:
                continue
            key = (str(candidate.get("type")), str(candidate.get("name")))
            recommendations[key] = {
                "type": candidate.get("type"),
                "name": candidate.get("name"),
                "fullname": candidate.get("fullname"),
                "rank_label": candidate.get("rank_label", "Unknown"),
                "rank_weight": candidate.get("rank_weight", -1),
                "description_snippet": candidate.get("description_snippet", ""),
                "cve_matches": shared,
                "cve_version_assessments": [
                    item for item in candidate.get("cve_version_assessments", [])
                    if str(item.get("cve_id", "")).upper() in shared
                ],
                "match_basis": "Shared CVE reference in finding and Metasploit module metadata; not proof of affected-version applicability or exploitability.",
            }

    ordered = sorted(
        recommendations.values(),
        key=lambda item: (item["rank_weight"], item["fullname"] or ""),
        reverse=True,
    )[:8]
    return {
        "finding_id": finding_id,
        "finding_title": finding.get("title"),
        "finding_status": finding.get("finding_status"),
        "target_context": {
            "target_id": approved["id"],
            "approved_target_url": approved["url"],
            "host": finding_origin[1],
            "port": finding_origin[2],
        },
        "recommendations": ordered,
        "notice": (
            "Recommendations are based on shared CVE references in finding and module metadata. "
            "They do not establish affected-version applicability, module compatibility, target "
            "vulnerability, or exploit success. No module check or execution was performed. "
            "Review module details and target options, then use the separate operator-controlled "
            "check-first and execution workflows."
        ),
    }
