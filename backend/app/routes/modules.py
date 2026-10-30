import base64
import binascii
import re
import time
from typing import Any, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.msf_rpc import rpc, MsfRpcError
from app.nvd_client import extract_cve_ids
from app.banner_parsing import parse_banner

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


# Metasploit's own module Rank values, ordered worst to best, so suggestions
# sort the same way local_exploit_suggester and the module browser do.
_RANK_ORDER = [
    "manual", "low", "average", "normal", "good", "great", "excellent",
]

# Maps a banner_parsing.py product name to the keyword(s) likely to appear
# in a matching exploit module's path/name. This is a search-term hint, not
# an identification: callers still see the module's own Rank/description/
# refs and decide for themselves, same as a manual module-browser search.
_PRODUCT_SEARCH_TERMS: dict[str, list[str]] = {
    "OpenSSH": ["openssh", "ssh"],
    "vsftpd": ["vsftpd"],
    "ProFTPD": ["proftpd"],
    "Pure-FTPd": ["pureftpd", "pure-ftpd", "pureftp"],
    "Microsoft FTP Service": ["ftp"],
    "Postfix": ["postfix"],
    "Exim": ["exim"],
    "Sendmail": ["sendmail"],
    "Microsoft Exchange/IIS SMTP": ["exchange", "smtp"],
    "Apache httpd": ["apache"],
    "nginx": ["nginx"],
    "Microsoft IIS": ["iis"],
    "lighttpd": ["lighttpd"],
    "Samba": ["samba"],
    "Windows": ["windows", "smb"],
    "MySQL": ["mysql"],
    "MariaDB": ["mysql", "mariadb"],
    "PostgreSQL": ["postgres"],
    "Redis": ["redis"],
    "Dovecot": ["dovecot"],
    "Courier": ["courier"],
    "RDP (TLS)": ["rdp"],
}


class ModuleSuggestion(BaseModel):
    name: str
    rank: str | None
    description: str
    cve_ids: list[str]


@router.get("/suggest")
def suggest_modules(detection_module: str, info: str, limit: int = 15):
    """
    Suggest candidate exploit modules for a *confirmed* service, the way
    msfconsole's own post/multi/recon/local_exploit_suggester matches
    confirmed services against exploit metadata - scoped here to one
    service's banner rather than a whole host's db.services.

    `detection_module` is the scanner module path that produced the
    confirmation (e.g. "scanner/ftp/ftp_version", matching
    versionDetection.ts), and `info` is that service's confirmed `info`
    string from db.services. Both are parsed server-side with
    banner_parsing.parse_banner so the frontend doesn't need to duplicate
    that parsing logic.

    This is a module-name/path search plus a sort by Metasploit's own
    Rank, not a vulnerability determination: a suggestion appearing here
    means "this module's name references the product that was confirmed,"
    not "this host is exploitable." The confirmed version is returned
    alongside each suggestion for the person to judge compatibility
    themselves (module Info pages rarely encode affected-version ranges in
    a machine-readable way), not used to filter results.
    """
    if not 1 <= limit <= 50:
        raise HTTPException(400, "limit must be between 1 and 50.")

    parsed = parse_banner(detection_module, info)
    if parsed is None:
        return {
            "product": None,
            "version": None,
            "search_terms": [],
            "suggestions": [],
            "note": "Could not identify a product/version from this confirmed banner.",
        }

    product, version = parsed.product, parsed.version
    search_terms = [term.lower() for term in _PRODUCT_SEARCH_TERMS.get(product, [product.lower()])]

    try:
        names = rpc.call("module.exploits").get("modules", [])
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))

    candidate_names = [
        name for name in names
        if any(term in name.lower() for term in search_terms)
    ]
    # Cap how many module.info calls we make per request - msfrpcd has no
    # bulk-info call, so this is one RPC round-trip per candidate.
    candidate_names = candidate_names[:60]

    suggestions: list[ModuleSuggestion] = []
    for name in candidate_names:
        try:
            info = rpc.call("module.info", "exploit", name)
        except MsfRpcError:
            continue
        if not isinstance(info, dict):
            continue
        description = str(info.get("description") or "").strip()
        # Keep the description short - the full text is already available
        # via the existing module-info panel if someone opens the module.
        if len(description) > 300:
            description = description[:300].rsplit(" ", 1)[0] + "…"
        suggestions.append(ModuleSuggestion(
            name=name,
            rank=str(info.get("rank")) if info.get("rank") is not None else None,
            description=description,
            cve_ids=sorted(extract_cve_ids(info)),
        ))

    def sort_key(s: ModuleSuggestion) -> int:
        rank = (s.rank or "").lower()
        return _RANK_ORDER.index(rank) if rank in _RANK_ORDER else -1

    suggestions.sort(key=sort_key, reverse=True)

    return {
        "product": product,
        "version": version,
        "search_terms": search_terms,
        "suggestions": [s.model_dump() for s in suggestions[:limit]],
    }


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
        detail = str(exc)
        # module.results often fails with no usable detail at all (see
        # msf_rpc.py's generic fallback message). Cross-check
        # module.running_stats so we can tell the caller *why*: the UUID is
        # still queued/running, or it was never recognized in the first
        # place (stale UUID, already purged by msfrpcd, or this Metasploit
        # build may not fully support module.results/module.running_stats).
        try:
            stats = rpc.call("module.running_stats")
        except MsfRpcError:
            stats = None
        if isinstance(stats, dict):
            waiting = stats.get("waiting") or []
            running = stats.get("running") or []
            completed = stats.get("results") or []
            if run_uuid in waiting:
                detail = f"{detail} Module run {run_uuid} is still waiting to start; try again shortly."
            elif run_uuid in running:
                detail = f"{detail} Module run {run_uuid} is still running; try again shortly."
            elif run_uuid not in completed:
                detail = (
                    f"{detail} Module run {run_uuid} was not found in module.running_stats "
                    "(waiting/running/results) at all. The UUID may be stale or already "
                    "purged by msfrpcd, or your Metasploit Framework build may not fully "
                    "support module.results/module.running_stats - check `msfconsole -v` "
                    "for your Framework version."
                )
        raise HTTPException(502, detail)


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



class EncodeRequest(BaseModel):
    name: str = Field(min_length=1, max_length=300)
    data: str = Field(min_length=1, max_length=200_000)
    data_format: Literal["text", "hex", "base64"] = "text"
    badchars: str = Field(default="", max_length=512)
    platform: str = Field(default="", max_length=80)
    arch: str = Field(default="", max_length=80)
    iterations: int = Field(default=1, ge=1, le=5)
    module_options: dict[str, Any] = Field(default_factory=dict)


class NopGenerateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=300)
    length: int = Field(default=256, ge=1, le=16384)
    badchars: str = Field(default="", max_length=512)
    save_registers: list[str] = Field(default_factory=list, max_length=16)


def _module_path_is_valid(name: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+", name))


def _hex_bytes(raw: str, label: str) -> bytes:
    compact = re.sub(r"(?i)(?:0x|\\x)|[\s,:]", "", raw)
    if compact and not re.fullmatch(r"(?:[0-9a-fA-F]{2})+", compact):
        raise HTTPException(400, f"{label} must be pairs of hexadecimal bytes, such as 00ff or \\\\x00\\\\xff.")
    try:
        return bytes.fromhex(compact)
    except ValueError as exc:
        raise HTTPException(400, f"{label} must contain valid hexadecimal bytes.") from exc


def _decode_encoder_input(req: EncodeRequest) -> bytes:
    if req.data_format == "text":
        return req.data.encode("utf-8")
    if req.data_format == "hex":
        data = _hex_bytes(req.data, "Input data")
        if not data:
            raise HTTPException(400, "Input data must not be empty.")
        return data
    try:
        data = base64.b64decode(req.data, validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise HTTPException(400, "Base64 input is invalid.") from exc
    if not data:
        raise HTTPException(400, "Input data must not be empty.")
    return data


def _safe_artifact_name(prefix: str, module_name: str, suffix: str = "bin") -> str:
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", module_name.replace("/", "-")).strip("-")[:100]
    slug = slug or "module-output"
    return f"{prefix}-{slug}.{suffix}"


def _raw_artifact_response(kind: str, filename: str, payload: Any, **metadata: Any) -> dict[str, Any]:
    if isinstance(payload, bytes):
        raw = payload
    elif isinstance(payload, bytearray):
        raw = bytes(payload)
    elif isinstance(payload, str):
        raw = payload.encode("utf-8")
    else:
        raise HTTPException(502, "Metasploit returned artifact data in an unsupported format.")
    if not raw:
        raise HTTPException(502, "Metasploit returned an empty artifact.")
    return {
        "kind": kind,
        "filename": filename,
        "size": len(raw),
        "payload_base64": base64.b64encode(raw).decode("ascii"),
        "format": "raw",
        **metadata,
    }


@router.post("/encode")
def encode_data(req: EncodeRequest):
    """Encode caller-provided bytes with one selected Metasploit encoder."""
    if not _module_path_is_valid(req.name):
        raise HTTPException(400, "Invalid encoder module name.")
    input_data = _decode_encoder_input(req)
    badchars = _hex_bytes(req.badchars, "Bad characters")
    try:
        encoder_result = rpc.call("module.encoders")
        encoders = encoder_result.get("modules", []) if isinstance(encoder_result, dict) else []
        if req.name not in encoders:
            raise HTTPException(404, f"Encoder module not found: {req.name}")

        option_result = rpc.call("module.options", "encoder", req.name)
        declared_options = option_result if isinstance(option_result, dict) else {}

        # Only pass options declared by the selected encoder. Keep RPC-level
        # formatting and filesystem-oriented options out of the caller's control.
        blocked = {
            "format", "badchars", "platform", "arch", "ecount", "inject",
            "altexe", "exedir", "template", "template_path", "addshellcode",
        }
        module_options = {
            key: value
            for key, value in req.module_options.items()
            if key in declared_options
            and key.lower() not in blocked
            and isinstance(value, (str, int, float, bool))
        }

        options: dict[str, Any] = {
            "format": "raw",
            "badchars": badchars,
            "ecount": req.iterations,
            **module_options,
        }
        if req.platform.strip():
            options["platform"] = req.platform.strip()
        if req.arch.strip():
            options["arch"] = req.arch.strip()

        result = rpc.call("module.encode", input_data, req.name, options)
        if not isinstance(result, dict) or "encoded" not in result:
            raise HTTPException(502, "Metasploit did not return encoded bytes.")
        artifact = _raw_artifact_response(
            "encoder",
            _safe_artifact_name("encoded", req.name),
            result["encoded"],
            module=req.name,
            input_size=len(input_data),
            iterations=req.iterations,
        )
        return artifact
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc)) from exc


def _run_console_command(console_id: str, command: str, timeout_seconds: float = 12.0) -> str:
    """Run one fixed-form command in a temporary Metasploit console and collect its output."""
    try:
        rpc.call("console.write", console_id, command + "\n")
        deadline = time.monotonic() + timeout_seconds
        output = ""
        idle_reads = 0
        while time.monotonic() < deadline:
            result = rpc.call("console.read", console_id)
            if not isinstance(result, dict):
                time.sleep(0.1)
                continue

            chunk = result.get("data")
            if chunk:
                output = (output + str(chunk))[-200_000:]
            if result.get("busy"):
                idle_reads = 0
            elif output:
                idle_reads += 1
                if idle_reads >= 2:
                    return output
            time.sleep(0.1)
        raise HTTPException(504, "Metasploit console command timed out. Check the Framework console and try again.")
    except MsfRpcError as exc:
        raise HTTPException(502, f"Metasploit console command failed: {exc}") from exc


@router.post("/generate-nops")
def generate_nops(req: NopGenerateRequest):
    """Generate a raw NOP sled using the selected module's native console dispatcher."""
    if not _module_path_is_valid(req.name):
        raise HTTPException(400, "Invalid NOP module name.")
    badchars = _hex_bytes(req.badchars, "Bad characters")
    if len(req.save_registers) > 16:
        raise HTTPException(400, "Too many registers were specified.")
    if any(not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,15}", register) for register in req.save_registers):
        raise HTTPException(400, "Save-register entries may contain letters and numbers only.")

    console_id: str | None = None
    try:
        nop_result = rpc.call("module.nops")
        nops = nop_result.get("modules", []) if isinstance(nop_result, dict) else []
        if req.name not in nops:
            raise HTTPException(404, f"NOP module not found: {req.name}")

        created = rpc.call("console.create")
        console_raw_id = created.get("id") if isinstance(created, dict) else None
        if console_raw_id is None:
            raise HTTPException(502, "Metasploit did not provide a console for NOP generation.")
        console_id = str(console_raw_id)
        # Drain the initial banner so the output parser only sees the commands below.
        try:
            rpc.call("console.read", console_id)
        except MsfRpcError:
            pass

        use_output = _run_console_command(console_id, f"use nop/{req.name}")
        if re.search(r"(?i)(failed to load|could not load|invalid module|no module selected)", use_output):
            raise HTTPException(502, f"Metasploit could not select NOP module '{req.name}'.")

        command_parts = ["generate", "-t", "c"]
        if badchars:
            command_parts.extend(["-b", badchars.hex()])
        if req.save_registers:
            command_parts.extend(["-s", ",".join(req.save_registers)])
        command_parts.append(str(req.length))
        generated_output = _run_console_command(console_id, " ".join(command_parts))

        if re.search(r"(?i)(sled generation failed|error:|invalid length|no module selected)", generated_output):
            raise HTTPException(502, f"Metasploit could not generate a NOP sled: {generated_output[-600:].strip()}")

        escaped_bytes = re.findall(r"\\x([0-9a-fA-F]{2})", generated_output)
        if not escaped_bytes:
            raise HTTPException(
                502,
                "Metasploit returned no recognizable binary data for the generated NOP sled.",
            )
        raw = bytes(int(value, 16) for value in escaped_bytes)
        if len(raw) != req.length:
            raise HTTPException(
                502,
                f"The selected NOP module returned {len(raw)} bytes; {req.length} were requested.",
            )

        return _raw_artifact_response(
            "nop",
            _safe_artifact_name(f"nop-{req.length}", req.name),
            raw,
            module=req.name,
            requested_size=req.length,
            badchars=req.badchars,
            save_registers=req.save_registers,
        )
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc)) from exc
    finally:
        if console_id is not None:
            try:
                rpc.call("console.destroy", console_id)
            except MsfRpcError:
                pass


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
