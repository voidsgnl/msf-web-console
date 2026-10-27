from fastapi import APIRouter, HTTPException
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


@router.get("/loot")
def loot():
    try:
        return rpc.call("db.loots", {})
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))


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
        raise HTTPException(502, str(exc))


@router.post("/workspaces")
def create_workspace(req: WorkspaceRequest):
    """Create a workspace and make it the active workspace."""
    name = _workspace_name(req.name)
    try:
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
        raise HTTPException(502, str(exc))
