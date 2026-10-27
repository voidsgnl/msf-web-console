from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.msf_rpc import rpc, MsfRpcError

router = APIRouter(prefix="/api/modules", tags=["modules"])

MODULE_TYPES = ["exploit", "auxiliary", "post", "payload", "encoder", "nop"]


@router.get("")
def list_modules(type: str = "exploit"):
    """List all module names of a given type (exploit/auxiliary/post/payload/encoder/nop)."""
    if type not in MODULE_TYPES:
        raise HTTPException(400, f"type must be one of {MODULE_TYPES}")
    try:
        names = rpc.call(f"module.{type}s")
        return {"type": type, "modules": names.get("modules", [])}
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))


@router.get("/search")
def search_modules(q: str, type: str | None = None):
    """
    Simple substring search across module names for a given type (or all types
    if omitted). The RPC API has no native search, so we pull the listing and
    filter here.
    """
    types = [type] if type in MODULE_TYPES else MODULE_TYPES
    results = []
    q_lower = q.lower()
    for t in types:
        try:
            names = rpc.call(f"module.{t}s").get("modules", [])
        except MsfRpcError:
            continue
        for name in names:
            if q_lower in name.lower():
                results.append({"type": t, "name": name})
    return {"query": q, "results": results[:200]}


@router.get("/{type}/{name:path}/info")
def module_info(type: str, name: str):
    if type not in MODULE_TYPES:
        raise HTTPException(400, f"type must be one of {MODULE_TYPES}")
    try:
        info = rpc.call("module.info", type, name)
        options = rpc.call("module.options", type, name)

        # Metasploit exposes compatible payloads through a dedicated RPC
        # method; module.info does not reliably include them in its metadata.
        compatible_payloads = None
        payloads_error = None
        if type == "exploit":
            try:
                payload_result = rpc.call("module.compatible_payloads", name)
                compatible_payloads = payload_result.get("payloads", [])
            except MsfRpcError as payload_exc:
                # Keep the regular module inspector usable if payload
                # compatibility lookup fails independently.
                payloads_error = str(payload_exc)

        return {
            "info": info,
            "options": options,
            "compatible_payloads": compatible_payloads,
            "payloads_error": payloads_error,
        }
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))


class ExecuteRequest(BaseModel):
    type: str
    name: str
    options: dict = {}


@router.post("/execute")
def execute_module(req: ExecuteRequest):
    """
    Execute a module via module.execute. For exploit/auxiliary/post this runs
    as a background job; the response includes a job_id (and uuid on newer
    msfrpcd) you can poll via /api/jobs or read results with job.info.
    """
    if req.type not in MODULE_TYPES:
        raise HTTPException(400, f"type must be one of {MODULE_TYPES}")
    try:
        result = rpc.call("module.execute", req.type, req.name, req.options)
        return result
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))
