from fastapi import APIRouter, HTTPException

from app.msf_rpc import rpc, MsfRpcError

router = APIRouter(prefix="/api/system", tags=["system"])


@router.get("/status")
def status():
    """Health check used by the frontend on load to confirm msfrpcd is reachable."""
    try:
        version = rpc.call("core.version")
        return {"connected": True, "version": version}
    except MsfRpcError as exc:
        return {"connected": False, "error": str(exc)}
