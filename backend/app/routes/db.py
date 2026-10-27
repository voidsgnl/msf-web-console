import hashlib
import json
import re
from typing import Any

from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel, Field

from app.msf_rpc import rpc, MsfRpcError

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


def _loot_bytes(value: Any) -> bytes | None:
    """Convert RPC loot data to bytes without touching server filesystem paths."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    return None


def _loot_fingerprint(record: dict[str, Any]) -> str:
    """Fingerprint the returned data and metadata because db.loots has no ID."""
    payload = _loot_bytes(record.get("data"))
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
    payload = _loot_bytes(record.get("data"))
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

    payload = _loot_bytes(selected.get("data"))
    if payload is None:
        raise HTTPException(
            404,
            "This loot record has no artifact data available through the Metasploit RPC response.",
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
