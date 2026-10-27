import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel, Field

from app.msf_rpc import rpc, MsfRpcError
from app.reporting import build_assessment_report
from app.pdf_reporting import build_assessment_report_pdf

router = APIRouter(prefix="/api/db", tags=["database"])


class WorkspaceRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)


def _workspace_name(raw_name: str) -> str:
    name = raw_name.strip()
    if not name:
        raise HTTPException(400, "Workspace name must not be blank.")
    return name


def _rpc_error(exc: MsfRpcError) -> HTTPException:
    # Metasploit uses 404 for a workspace that cannot be found. Other RPC
    # failures indicate an upstream/database problem and remain 502 responses.
    status_code = 404 if str(exc.error_code) == "404" else 502
    return HTTPException(status_code, str(exc))


@router.get("/hosts")
def hosts():
    try:
        return rpc.call("db.hosts", {})
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))


@router.get("/services")
def services():
    try:
        return rpc.call("db.services", {})
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))


@router.get("/vulns")
def vulns():
    try:
        return rpc.call("db.vulns", {})
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))


MAX_LOOT_FILE_BYTES = 256 * 1024 * 1024


def _loot_bytes(value: Any) -> bytes | None:
    """Convert inline RPC loot data to bytes."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    return None


def _configured_loot_paths(variable: str) -> list[Path]:
    raw = os.getenv(variable, "")
    return [
        Path(entry).expanduser().resolve()
        for entry in raw.split(os.pathsep)
        if entry.strip()
    ]


def _read_registered_loot_file(record: dict[str, Any]) -> bytes | None:
    """
    Read a loot file only when its database-reported path is explicitly allowed.

    By default only ~/.msf4/loot is allowed. Operators may add specific files
    or directories through MSF_LOOT_ALLOWED_FILES and MSF_LOOT_ALLOWED_DIRS.
    Client requests never supply a filesystem path.
    """
    raw_path = record.get("path")
    if not isinstance(raw_path, str) or not raw_path.strip():
        return None

    try:
        candidate = Path(raw_path).expanduser().resolve(strict=True)
        if not candidate.is_file():
            return None

        allowed_dirs = _configured_loot_paths("MSF_LOOT_ALLOWED_DIRS")
        if not os.getenv("MSF_LOOT_ALLOWED_DIRS"):
            allowed_dirs = [(Path.home() / ".msf4" / "loot").resolve()]

        allowed_files = _configured_loot_paths("MSF_LOOT_ALLOWED_FILES")
        is_allowed_dir = any(candidate.is_relative_to(root) for root in allowed_dirs)
        is_allowed_file = candidate in allowed_files
        if not (is_allowed_dir or is_allowed_file):
            return None

        if candidate.stat().st_size > MAX_LOOT_FILE_BYTES:
            return None

        with candidate.open("rb") as stream:
            payload = stream.read(MAX_LOOT_FILE_BYTES + 1)
        return payload if len(payload) <= MAX_LOOT_FILE_BYTES else None
    except (OSError, RuntimeError, ValueError):
        return None


def _loot_payload(record: dict[str, Any]) -> bytes | None:
    """Prefer bytes from RPC; fall back to an allowlisted database-registered file."""
    inline = _loot_bytes(record.get("data"))
    return inline if inline is not None else _read_registered_loot_file(record)


def _loot_fingerprint(record: dict[str, Any]) -> str:
    """Fingerprint metadata and artifact bytes without exposing a server path."""
    payload = _loot_payload(record)
    identity = {
        key: record.get(key)
        for key in ("name", "ltype", "ctype", "host", "service", "created_at", "updated_at", "info")
    }
    identity["data_sha256"] = hashlib.sha256(payload).hexdigest() if payload is not None else None
    canonical = json.dumps(identity, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _loot_download_id(record: dict[str, Any], offset: int = 0) -> str:
    """Return a page offset plus fingerprint; the server verifies both on download."""
    return f"{offset}.{_loot_fingerprint(record)}"


def _public_loot_record(record: dict[str, Any], offset: int = 0) -> dict[str, Any]:
    """Return safe metadata only; keep potentially large/sensitive artifact bytes server-side."""
    public = {key: value for key, value in record.items() if key != "data" and "path" not in key.lower()}
    payload = _loot_payload(record)
    public["download_id"] = _loot_download_id(record, offset)
    public["has_data"] = payload is not None
    public["size"] = len(payload) if payload is not None else None
    return public


def _safe_loot_filename(value: Any) -> str:
    raw_name = str(value or "loot-artifact.bin").replace("\\", "/").split("/")[-1]
    filename = re.sub(r"[^A-Za-z0-9._-]+", "_", raw_name).lstrip(".")
    return filename[:120] or "loot-artifact.bin"


def _safe_content_type(value: Any) -> str:
    candidate = str(value or "")
    if re.fullmatch(r"[A-Za-z0-9!#_.+-]+/[A-Za-z0-9!#_.+-]+", candidate):
        return candidate
    return "application/octet-stream"


@router.get("/loot")
def loot():
    """List loot metadata without transferring raw artifact data to the browser."""
    try:
        result = rpc.call("db.loots", {})
        records = result.get("loots", []) if isinstance(result, dict) else []
        return {
            "loot": [
                _public_loot_record(record, offset)
                for offset, record in enumerate(records)
                if isinstance(record, dict)
            ]
        }
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))


@router.get("/loot/{download_id}/download")
def download_loot(download_id: str):
    """Download returned loot data by verified page offset, never a user-supplied path."""
    match = re.fullmatch(r"(\d{1,3})\.([a-f0-9]{64})", download_id)
    if not match:
        raise HTTPException(400, "Invalid loot download reference.")

    offset = int(match.group(1))
    if offset >= 100:
        raise HTTPException(400, "Invalid loot download offset. Refresh the loot list.")

    try:
        result = rpc.call("db.loots", {"limit": 1, "offset": offset})
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))

    records = result.get("loots", []) if isinstance(result, dict) else []
    selected = records[0] if records and isinstance(records[0], dict) else None
    if selected is None or _loot_fingerprint(selected) != match.group(2):
        raise HTTPException(404, "Loot record changed or was not found. Refresh the loot list and try again.")

    payload = _loot_payload(selected)
    if payload is None:
        raise HTTPException(
            404,
            "Artifact bytes are unavailable. If the loot record points to a file, add that exact file or its directory to MSF_LOOT_ALLOWED_FILES or MSF_LOOT_ALLOWED_DIRS in backend/.env, then restart the backend.",
        )

    filename = _safe_loot_filename(selected.get("name"))
    return Response(
        content=payload,
        media_type=_safe_content_type(selected.get("ctype")),
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )


def _assessment_snapshot() -> tuple[str, dict[str, list[dict[str, Any]]]]:
    """Collect one active-workspace snapshot for either HTML or PDF exports."""
    try:
        workspace_result = rpc.call("db.current_workspace")
        workspace = (
            str(workspace_result.get("workspace") or "default")
            if isinstance(workspace_result, dict)
            else "default"
        )
        datasets = (
            ("hosts", "db.hosts", "hosts"),
            ("services", "db.services", "services"),
            ("vulns", "db.vulns", "vulns"),
            ("creds", "db.creds", "creds"),
            ("loot", "db.loots", "loots"),
        )
        records: dict[str, list[dict[str, Any]]] = {}
        for section, method, result_key in datasets:
            result = rpc.call(method, {})
            rows = result.get(result_key, []) if isinstance(result, dict) else []
            valid_rows = [row for row in rows if isinstance(row, dict)]
            if section == "loot":
                sanitized_loot: list[dict[str, Any]] = []
                for row in valid_rows:
                    payload = _loot_payload(row)
                    metadata = {
                        key: value
                        for key, value in row.items()
                        if key != "data" and "path" not in key.lower()
                    }
                    metadata["has_data"] = payload is not None
                    metadata["size"] = len(payload) if payload is not None else None
                    sanitized_loot.append(metadata)
                records[section] = sanitized_loot
            else:
                records[section] = valid_rows
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc)) from exc
    return workspace, records


def _assessment_filename(workspace: str, extension: str) -> str:
    from datetime import datetime, timezone

    safe_workspace = re.sub(r"[^A-Za-z0-9_-]+", "_", workspace or "default").strip("_")[:80]
    safe_workspace = safe_workspace or "default"
    date = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"msf-assessment-{safe_workspace}-{date}.{extension}"


def _assessment_download_headers(filename: str) -> dict[str, str]:
    return {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
    }


@router.get("/report")
def download_assessment_report():
    """Download a sanitized HTML snapshot of the active workspace."""
    workspace, records = _assessment_snapshot()
    report = build_assessment_report(workspace, records)
    return Response(
        content=report,
        media_type="text/html",
        headers=_assessment_download_headers(_assessment_filename(workspace, "html")),
    )


@router.get("/report.pdf")
def download_assessment_report_pdf():
    """Download a sanitized native PDF snapshot of the active workspace."""
    workspace, records = _assessment_snapshot()
    report = build_assessment_report_pdf(workspace, records)
    return Response(
        content=report,
        media_type="application/pdf",
        headers=_assessment_download_headers(_assessment_filename(workspace, "pdf")),
    )


@router.get("/creds")
def creds():
    try:
        return rpc.call("db.creds", {})
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))


@router.get("/workspaces")
def workspaces():
    try:
        return rpc.call("db.workspaces")
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))


@router.get("/workspace")
def current_workspace():
    """Return the workspace currently selected by the Metasploit RPC framework."""
    try:
        return rpc.call("db.current_workspace")
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))


@router.post("/workspace")
def set_workspace(req: WorkspaceRequest):
    """Switch the active Metasploit database workspace."""
    name = _workspace_name(req.name)
    try:
        result = rpc.call("db.set_workspace", name)
        if not isinstance(result, dict) or result.get("result") != "success":
            raise HTTPException(404, f"Workspace not found: {name}")
        return rpc.call("db.current_workspace")
    except MsfRpcError as exc:
        raise _rpc_error(exc)


@router.delete("/workspaces/{name:path}")
def delete_workspace(name: str):
    """Delete a named workspace, protecting Metasploit's default workspace."""
    workspace_name = _workspace_name(name)
    if workspace_name.casefold() == "default":
        raise HTTPException(400, "The default workspace is protected and cannot be deleted.")

    try:
        listed = rpc.call("db.workspaces")
        available = listed.get("workspaces", []) if isinstance(listed, dict) else []
        if not any(
            isinstance(workspace, dict) and workspace.get("name") == workspace_name
            for workspace in available
        ):
            raise HTTPException(404, f"Workspace not found: {workspace_name}")

        result = rpc.call("db.del_workspace", workspace_name)
        if not isinstance(result, dict) or result.get("result") != "success":
            raise HTTPException(502, f"Metasploit did not confirm deletion of workspace: {workspace_name}")

        current = rpc.call("db.current_workspace")
        refreshed = rpc.call("db.workspaces")
        return {
            "deleted_workspace": workspace_name,
            "current_workspace": current,
            "workspaces": refreshed.get("workspaces", []) if isinstance(refreshed, dict) else [],
        }
    except MsfRpcError as exc:
        raise _rpc_error(exc)


@router.post("/workspaces")
def create_workspace(req: WorkspaceRequest):
    """Create a workspace and make it the active workspace."""
    name = _workspace_name(req.name)
    try:
        current_workspaces = rpc.call("db.workspaces").get("workspaces", [])
        if any(workspace.get("name") == name for workspace in current_workspaces):
            raise HTTPException(409, f"Workspace already exists: {name}")

        result = rpc.call("db.add_workspace", name)
        if not isinstance(result, dict) or result.get("result") != "success":
            raise HTTPException(
                409,
                f"Could not create workspace '{name}'. It may already exist.",
            )

        switched = rpc.call("db.set_workspace", name)
        if not isinstance(switched, dict) or switched.get("result") != "success":
            raise HTTPException(
                502,
                f"Workspace '{name}' was created, but Metasploit could not switch to it.",
            )
        return rpc.call("db.current_workspace")
    except MsfRpcError as exc:
        raise _rpc_error(exc)
