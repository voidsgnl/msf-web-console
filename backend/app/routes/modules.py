import base64
import re
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.msf_rpc import rpc, MsfRpcError

router = APIRouter(prefix="/api/modules", tags=["modules"])

MODULE_TYPES = ["exploit", "auxiliary", "post", "payload", "encoder", "nop"]
EXECUTABLE_TYPES = {"exploit", "auxiliary", "post", "payload"}
RUN_UUID_RE = re.compile(r"^[A-Za-z0-9]{12,64}$")


@router.get("")
def list_modules(type: str = "exploit"):
    """List all module names of a given type."""
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
    Simple substring search across module names. The RPC API has no native
    search, so pull the listing and filter it here.
    """
    if type is not None and type not in MODULE_TYPES:
        raise HTTPException(400, f"type must be one of {MODULE_TYPES}")

    types = [type] if type else MODULE_TYPES
    results = []
    q_lower = q.lower()
    for module_type in types:
        try:
            names = rpc.call(f"module.{module_type}s").get("modules", [])
        except MsfRpcError as exc:
            raise HTTPException(502, f"Could not search {module_type} modules: {exc}") from exc
        for name in names:
            if q_lower in name.lower():
                results.append({"type": module_type, "name": name})
                if len(results) >= 200:
                    return {"query": q, "results": results}
    return {"query": q, "results": results}


@router.get("/compatible-payloads")
def compatible_payloads(name: str, target: int | None = None):
    """Return all compatible payloads or those compatible with one exploit target."""
    try:
        if target is None:
            result = rpc.call("module.compatible_payloads", name)
        else:
            result = rpc.call("module.target_compatible_payloads", name, target)
        return {
            "module": name,
            "target": target,
            "payloads": result.get("payloads", []),
        }
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))


@router.get("/running-stats")
def module_running_stats():
    """Return Metasploit's waiting, running, and completed module run UUIDs."""
    try:
        result = rpc.call("module.running_stats")
        return result if isinstance(result, dict) else {"waiting": [], "running": [], "results": []}
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))


@router.get("/results/{run_uuid}")
def module_result(run_uuid: str):
    """Fetch the final or current result for a module run UUID."""
    if not RUN_UUID_RE.fullmatch(run_uuid):
        raise HTTPException(400, "Invalid module run UUID.")
    try:
        result = rpc.call("module.results", run_uuid)
        return result if isinstance(result, dict) else {"status": "unknown", "result": result}
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))


@router.get("/{type}/{name:path}/info")
def module_info(type: str, name: str):
    if type not in MODULE_TYPES:
        raise HTTPException(400, f"type must be one of {MODULE_TYPES}")
    try:
        info = rpc.call("module.info", type, name)
        options = rpc.call("module.options", type, name)
        return {"info": info, "options": options}
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))


class ExecuteRequest(BaseModel):
    type: str
    name: str = Field(min_length=1, max_length=300)
    options: dict[str, Any] = Field(default_factory=dict)


def _payload_filename(module_name: str, options: dict[str, Any]) -> str:
    name = module_name.replace("\\", "/").split("/")[-1]
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip(".")[:100] or "generated-payload"
    requested_format = str(options.get("Format") or options.get("format") or "").strip().lower()
    extension = requested_format if re.fullmatch(r"[a-z0-9]{1,8}", requested_format) else "bin"
    return f"{stem}.{extension}"


def _payload_response(result: Any, module_name: str, options: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(result, dict) or "payload" not in result:
        raise HTTPException(502, "Metasploit did not return generated payload bytes.")
    payload = result["payload"]
    if isinstance(payload, bytes):
        payload_bytes = payload
    elif isinstance(payload, bytearray):
        payload_bytes = bytes(payload)
    elif isinstance(payload, str):
        payload_bytes = payload.encode("utf-8")
    else:
        raise HTTPException(502, "Metasploit returned payload data in an unsupported format.")

    return {
        "kind": "payload",
        "filename": _payload_filename(module_name, options),
        "size": len(payload_bytes),
        "payload_base64": base64.b64encode(payload_bytes).decode("ascii"),
        "format": str(options.get("Format") or options.get("format") or "raw"),
    }


@router.post("/execute")
def execute_module(req: ExecuteRequest):
    """
    Execute exploit/auxiliary/post modules as jobs, or generate a payload.
    Encoder and NOP modules require dedicated encode/generate workflows and
    are deliberately rejected here instead of being sent to module.execute.
    """
    if req.type not in MODULE_TYPES:
        raise HTTPException(400, f"type must be one of {MODULE_TYPES}")
    if req.type not in EXECUTABLE_TYPES:
        raise HTTPException(
            400,
            f"Direct execution is not supported for {req.type} modules. "
            "Encoder and NOP generation need a dedicated workflow.",
        )
    try:
        result = rpc.call("module.execute", req.type, req.name, req.options)
        if req.type == "payload":
            return _payload_response(result, req.name, req.options)
        if not isinstance(result, dict):
            raise HTTPException(502, "Metasploit returned an unexpected module execution response.")
        return result
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))
