import base64
import binascii
import re
import time
from typing import Any, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.msf_rpc import rpc, MsfRpcError
from app.banner_parsing import parse_service_banner
from app.nvd_client import NvdError, extract_cve_ids, nvd_client

router = APIRouter(prefix="/api/modules", tags=["modules"])

MODULE_TYPES = ["exploit", "auxiliary", "post", "payload", "encoder", "nop"]
MODULE_LIST_RPC_METHODS = {
    "exploit": "module.exploits",
    "auxiliary": "module.auxiliary",
    "post": "module.post",
    "payload": "module.payloads",
    "encoder": "module.encoders",
    "nop": "module.nops",
}
EXECUTABLE_TYPES = {"exploit", "auxiliary", "post", "payload"}
RUN_UUID_RE = re.compile(r"^[A-Za-z0-9]{12,64}$")


@router.get("")
def list_modules(type: str = "exploit"):
    """List all module names of a given type."""
    if type not in MODULE_TYPES:
        raise HTTPException(400, f"type must be one of {MODULE_TYPES}")
    try:
        names = rpc.call(MODULE_LIST_RPC_METHODS[type])
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
            names = rpc.call(MODULE_LIST_RPC_METHODS[module_type]).get("modules", [])
        except MsfRpcError as exc:
            raise HTTPException(502, f"Could not search {module_type} modules: {exc}") from exc
        for name in names:
            if q_lower in name.lower():
                results.append({"type": module_type, "name": name})
                if len(results) >= 200:
                    return {"query": q, "results": results}
    return {"query": q, "results": results}


# Metasploit's internal module Rank constants (Msf::RankingName / the
# integers module.info's "rank" field is built from). Declared high-to-low
# so "snap to nearest known rung" below is a simple linear scan.
RANK_LABELS: list[tuple[int, str]] = [
    (600, "Excellent"),
    (500, "Great"),
    (400, "Good"),
    (300, "Normal"),
    (200, "Average"),
    (100, "Low"),
    (0, "Manual"),
]
RANK_NAME_WEIGHTS = {name.lower(): weight for weight, name in RANK_LABELS}

# A shared CVE reference is useful corroborating evidence, but keywordSearch
# does not prove that the detected product version is in the CVE's affected
# CPE/version range. Keep Metasploit's native reliability rank untouched and
# use the overlap only as a separate relevance tie-breaker.



def _rank_weight_and_label(raw_rank: Any) -> tuple[int, str]:
    """
    Normalize module.info's "rank" field to (weight, label). Most msfrpcd
    builds return the raw integer (e.g. 600 for Excellent); fall back to
    matching a string name defensively in case a build returns that instead.
    """
    if isinstance(raw_rank, bool):
        return -1, "Unknown"
    if isinstance(raw_rank, (int, float)):
        weight = int(raw_rank)
        label = next((name for threshold, name in RANK_LABELS if weight >= threshold), "Unknown")
        return weight, label
    if isinstance(raw_rank, str):
        weight = RANK_NAME_WEIGHTS.get(raw_rank.strip().lower())
        if weight is not None:
            return weight, raw_rank.strip().capitalize()
    return -1, "Unknown"


_SOFTWARE_NAME_RE = re.compile(r"[A-Za-z]{2,}")
# Generic banner words that aren't useful as a module-name search term on
# their own (protocol/transport/vendor words that show up in almost every
# banner, regardless of which actual software is running). "Microsoft" is
# here so a banner like "Microsoft SQL Server" falls through to "sql",
# which actually substring-matches Metasploit's "mssql" module paths.
_GENERIC_BANNER_WORDS = {
    "the", "server", "service", "version", "ssh", "http", "https", "ftp",
    "smtp", "pop3", "imap", "protocol", "running", "unknown", "open",
    "ready", "welcome", "connection", "for", "and", "build", "via",
    "microsoft",
}


def _extract_search_term(service_info: str) -> str | None:
    """
    Pull a plausible software-name token out of a CONFIRMED service banner
    (e.g. "vsftpd 2.3.4" -> "vsftpd", "OpenSSH 7.2p2 Ubuntu" -> "openssh").
    Letters-only tokenization on purpose: splitting on digits/punctuation
    first avoids gluing version numbers onto the software name (naive
    "keep alnum+.-_ together" tokenizing would turn "OpenSSH_7.2p2" into
    one useless token that matches no real module name). This is
    deliberately simple substring extraction to narrow Metasploit's own
    module list - not a claim of parsing every banner correctly.
    """
    for token in _SOFTWARE_NAME_RE.findall(service_info):
        lowered = token.lower()
        if lowered in _GENERIC_BANNER_WORDS:
            continue
        return lowered
    return None


@router.get("/suggest")
def suggest_modules(service_info: str, port: int | None = None, types: str | None = None):
    """
    Heuristically match a CONFIRMED service banner (from an actual
    version-detection scan, not a port-number guess) against Metasploit's
    own module names, and rank the matches by Metasploit's own module Rank.

    This mirrors the spirit of post/multi/recon/local_exploit_suggester -
    ranked, software-specific suggestions - without its most expensive and
    most intrusive step: local_exploit_suggester actually runs every
    candidate module's `check` against the live target. A name/description
    match here is NOT a vulnerability confirmation. Use
    POST /modules/{type}/{name}/check to actually verify a specific
    candidate against the target before trusting it.

    When a service banner is confirmed, candidates are cross-referenced
    against NVD keyword-search results. A `cve_matches` entry means the
    module metadata and NVD search results share a CVE identifier. This is
    corroborating reference evidence only: keywordSearch does not establish
    that the detected product/version is in that CVE's affected CPE range.
    It is not proof that the target is vulnerable and does not change
    Metasploit's native reliability rank.
    """
    term = _extract_search_term(service_info)
    parsed = parse_service_banner(service_info, port)

    # Port-based hints are lower-confidence fallbacks when no service banner
    # is available. They identify likely service families, not vulnerabilities.
    port_hints = {
        21: ["ftp"], 22: ["ssh"], 23: ["telnet"], 25: ["smtp"],
        53: ["dns"], 80: ["http"], 110: ["pop3"], 111: ["rpc"],
        135: ["msrpc"], 139: ["smb"], 143: ["imap"], 161: ["snmp"],
        389: ["ldap"], 443: ["http"], 445: ["smb"], 465: ["smtp"],
        587: ["smtp"], 631: ["cups"], 993: ["imap"], 995: ["pop3"],
        1433: ["mssql"], 1521: ["oracle"], 2049: ["nfs"],
        2375: ["docker"], 3306: ["mysql"], 3389: ["rdp"],
        5432: ["postgres"], 5900: ["vnc"], 6379: ["redis"],
        8000: ["http"], 8080: ["http"], 8081: ["http"],
        8443: ["http"], 9200: ["elasticsearch"], 27017: ["mongodb"],
    }

    terms: list[str] = []
    prod_lower = parsed.product.lower() if parsed and parsed.product else ""
    if prod_lower:
        if "apache tomcat" in prod_lower or "tomcat" in prod_lower:
            terms.extend(["tomcat", "coyote"])
        elif "apache httpd" in prod_lower or "apache" in prod_lower:
            terms.extend(["apache", "httpd"])
        elif "iis" in prod_lower:
            terms.extend(["iis"])
        elif "nginx" in prod_lower:
            terms.extend(["nginx"])
        elif "samba" in prod_lower:
            terms.extend(["samba", "smb"])
        elif "openssh" in prod_lower or "ssh" in prod_lower:
            terms.extend(["ssh"])
        elif "postgres" in prod_lower:
            terms.extend(["postgres", "postgresql"])
        elif "mysql" in prod_lower or "mariadb" in prod_lower:
            terms.extend(["mysql", "mariadb"])
        elif "redis" in prod_lower:
            terms.extend(["redis"])
        else:
            clean_tokens = [t.lower() for t in _SOFTWARE_NAME_RE.findall(parsed.product) if t.lower() not in _GENERIC_BANNER_WORDS]
            terms.extend(clean_tokens)

    # Once a banner parser has identified the product, trust those product
    # terms rather than re-adding the first raw token (e.g. "apache" from an
    # Apache-Coyote Tomcat banner).
    if term and term not in terms and term not in ("openssh",) and not parsed:
        terms.append(term)

    if not terms:
        terms = port_hints.get(port or 0, [])

    if not terms:
        return {
            "query": None,
            "candidates": [],
            "note": "No banner was identified and this port has no built-in service-family hint. Confirm the service version or investigate manually.",
        }

    query_label = terms[0] if parsed else (term or terms[0])
    match_basis = (
        f"confirmed service banner matched '{parsed.product if parsed else term}'"
        if (parsed or term) else f"common service mapping for TCP port {port} ({terms[0]})"
    )

    requested_types = [t.strip() for t in types.split(",")] if types else ["exploit", "auxiliary"]
    search_types = [t for t in requested_types if t in MODULE_TYPES] or ["exploit", "auxiliary"]

    raw_matches: list[dict[str, str]] = []
    try:
        for module_type in search_types:
            names = rpc.call(MODULE_LIST_RPC_METHODS[module_type]).get("modules", [])
            for name in names:
                name_lower = name.lower()
                if any(search_term in name_lower for search_term in terms):
                    raw_matches.append({"type": module_type, "name": name})
    except MsfRpcError as exc:
        raise HTTPException(502, f"Could not search modules: {exc}") from exc

    if not raw_matches:
        return {"query": query_label, "candidates": [], "note": f"No module names matched {query_label}."}

    # Cross-reference the confirmed product/version against NVD's own CVE
    # corpus (independent of Metasploit) so candidates can be checked for a
    # genuine CVE-to-module match below, rather than only a name match.
    # Best-effort: NVD being unreachable/rate-limited must not break name
    # matching, which already worked before this cross-check existed.
    known_cve_ids: set[str] = set()
    cve_lookup_error: str | None = None
    if parsed and parsed.product:
        try:
            known_cve_ids = nvd_client.search_cve_ids_by_keyword(parsed.product, parsed.version)
        except NvdError as exc:
            cve_lookup_error = str(exc)

    # Version tokens for relevance scoring
    version_tokens: list[str] = []
    if parsed and parsed.version and parsed.version != "unknown":
        v = parsed.version.lower()
        version_tokens.append(v)
        v_no_dot = v.replace(".", "")
        if v_no_dot != v:
            version_tokens.append(v_no_dot)
        v_under = v.replace(".", "_")
        if v_under != v:
            version_tokens.append(v_under)
        parts = v.split(".")
        if len(parts) >= 2:
            version_tokens.append(f"{parts[0]}.{parts[1]}")
            version_tokens.append(f"{parts[0]}_{parts[1]}")

    other_apache_projects = (
        'airflow', 'couchdb', 'druid', 'solr', 'spark', 'nifi', 'ofbiz', 'activemq',
        'continuum', 'hugegraph', 'flink', 'superset', 'struts', 'tika', 'myfaces',
        'wicket', 'jspwiki', 'jackrabbit', 'apisix', 'roller', 'jetspeed', 'rocketmq', 'james'
    )

    def score_match(match: dict[str, str]) -> int:
        score = 0
        m_name = match["name"].lower()
        m_type = match["type"]

        # OpenSSH / SSH family scoring
        if "openssh" in prod_lower or "ssh" in prod_lower or port == 22:
            if any(k in m_name for k in ['ssh_login', 'ssh_enumusers', 'ssh_identify_pubkeys']):
                score += 450
            elif m_type == "auxiliary":
                score += 200
            elif any(k in m_name for k in ['cisco', 'ceragon', 'f5_bigip', 'exagrid', 'quantum', 'solarwinds']):
                score -= 150
            return score

        # Apache HTTP Server filtering
        if "apache httpd" in prod_lower or (port in (80, 443, 8080, 8443) and "apache" in prod_lower and "tomcat" not in prod_lower):
            if any(proj in m_name for proj in other_apache_projects):
                score -= 500
            if any(k in m_name for k in ['normalize_path', 'mod_cgi', 'optionsbleed', 'userdir_enum', 'chunked', 'httpd']):
                score += 300

        # General exploit priority
        if m_type == "exploit":
            score += 150

        # Version substring matching in module path
        for vt in version_tokens:
            if vt in m_name:
                score += 400
                break

        # Preferred platforms
        if any(m_name.startswith(p) for p in ("multi/", "linux/", "windows/", "unix/")):
            score += 60

        # Penalize legacy/rare architectures
        if any(m_name.startswith(p) for p in ("aix/", "solaris/", "netware/", "hpux/", "irix/", "bsdi/", "osx/")):
            score -= 200

        # Service family affinity
        if port in (80, 443, 8000, 8080, 8081, 8443) and "/http/" in m_name:
            score += 80
        elif port == 21 and "/ftp/" in m_name:
            score += 80
        elif port in (139, 445) and "/smb/" in m_name:
            score += 80

        return score

    raw_matches.sort(key=score_match, reverse=True)
    candidate_pool = [m for m in raw_matches if score_match(m) > -100][:25]

    candidates: list[dict[str, Any]] = []
    has_version_match = False
    has_cve_match = False
    for match in candidate_pool:
        try:
            info = rpc.call("module.info", match["type"], match["name"])
        except MsfRpcError:
            continue
        if not isinstance(info, dict):
            continue
        weight, label = _rank_weight_and_label(info.get("rank"))
        description = str(info.get("description") or "").strip()
        snippet = description.split("\n", 1)[0][:220]

        # A shared identifier is a cross-reference signal, not affected-
        # version validation. Keep it separate from Metasploit's rank.
        module_cve_ids = extract_cve_ids(info.get("references"))
        cve_matches = sorted(module_cve_ids & known_cve_ids)

        # Keep the displayed rank faithful to Metasploit's native rank.
        # Version and CVE evidence affect relevance ordering only.
        adjusted_weight = weight
        if any(vt in description.lower() for vt in version_tokens):
            has_version_match = True
        if cve_matches:
            has_cve_match = True
        candidates.append({
            "type": match["type"],
            "name": match["name"],
            "fullname": info.get("fullname") or f"{match['type']}/{match['name']}",
            "rank_weight": adjusted_weight,
            "rank_label": label,
            "disclosure_date": info.get("disclosure_date"),
            "description_snippet": snippet,
            "match_basis": match_basis,
            "cve_matches": cve_matches,
        })

    candidates.sort(
        key=lambda c: (
            bool(c["cve_matches"]),
            c["rank_weight"],
            c.get("disclosure_date") or "",
        ),
        reverse=True,
    )

    # Dynamic plain-language note describing the findings
    if has_cve_match:
        cve_note_target = f"{parsed.product} {parsed.version}" if parsed.version != "unknown" else parsed.product
        note = (
            f"Confirmed {cve_note_target}. One or more candidates share a CVE reference with NVD keyword-search "
            f"results for this product query. This is useful cross-reference evidence, but it does not validate "
            f"the detected version against the CVE's affected-version range and is not proof the target is "
            f"vulnerable. Review the CVE references and use Verify where the module supports a check."
        )
    elif parsed and "openssh" in prod_lower:
        note = f"Confirmed {parsed.product} {parsed.version if parsed.version != 'unknown' else ''}. SSH services are typically tested via credential login and enumeration modules rather than direct exploits."
    elif parsed and parsed.version and parsed.version != "unknown":
        if has_version_match:
            note = f"Confirmed {parsed.product} {parsed.version} with specific version-matched module."
        else:
            note = f"Confirmed {parsed.product} {parsed.version}. Showing service verification and reconnaissance modules."
    elif parsed:
        note = f"Confirmed {parsed.product}. Showing relevant service modules."
    else:
        note = f"Service on port {port} (inferred {terms[0]}). Showing relevant modules."

    if cve_lookup_error:
        note = f"{note} (NVD CVE cross-check unavailable: {cve_lookup_error})"

    return {"query": query_label, "candidates": candidates[:8], "note": note}


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


class ModuleCheckRequest(BaseModel):
    options: dict[str, Any] = Field(default_factory=dict)


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


ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]|\x1b\([a-zA-Z]")


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
                clean_chunk = ANSI_ESCAPE_RE.sub("", str(chunk))
                output = (output + clean_chunk)[-200_000:]
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


_CHECK_SETTABLE_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
# Order matters: "not vulnerable" also contains the substring "vulnerable",
# so the negative pattern is always tested before the positive one.
_CHECK_NOT_VULNERABLE_RE = re.compile(
    r"(?i)(is not vulnerable|not vulnerable|not exploitable|cannot be exploited|"
    r"appears (to be )?safe|the target is not vulnerable)"
)
_CHECK_UNSUPPORTED_RE = re.compile(
    r"(?i)(does not support .{0,12}check|unknown command: check|checkcode::unsupported)"
)
_CHECK_UNKNOWN_RE = re.compile(
    r"(?i)(unsupported target|could not be reliably checked|cannot reliably check|"
    r"state could not be determined|unable to check|connection refused|"
    r"unreachable|check failed|checkcode::unknown)"
)
_CHECK_VULNERABLE_RE = re.compile(
    r"(?i)(the target is vulnerable|appears (to be )?vulnerable|is vulnerable|"
    r"checkcode::vulnerable|checkcode::appears)"
)


def _check_verdict(output: str) -> str:
    # Explicit Metasploit CheckCode values are authoritative. A service being
    # reachable/running is only evidence of service availability, never a
    # vulnerability verdict.
    if re.search(r"(?i)checkcode::vulnerable|checkcode::appears", output):
        return "vulnerable"
    if re.search(r"(?i)checkcode::safe", output):
        return "not_vulnerable"
    if _CHECK_UNSUPPORTED_RE.search(output):
        return "unsupported"
    if _CHECK_UNKNOWN_RE.search(output):
        return "unknown"
    if _CHECK_NOT_VULNERABLE_RE.search(output):
        return "not_vulnerable"
    if _CHECK_VULNERABLE_RE.search(output):
        return "vulnerable"
    return "unknown"


@router.post("/{type}/{name:path}/check")
def _missing_required_check_options(
    declared_options: Any,
    supplied_options: dict[str, Any],
) -> list[str]:
    """Return required module options that have neither a supplied value nor a default."""
    if not isinstance(declared_options, dict):
        return []
    missing: list[str] = []
    for option_name, definition in declared_options.items():
        if not isinstance(definition, dict) or not definition.get("required"):
            continue
        supplied = supplied_options.get(option_name)
        default = definition.get("default")
        if supplied is None or (isinstance(supplied, str) and not supplied.strip()):
            if default is None or (isinstance(default, str) and not default.strip()):
                missing.append(str(option_name))
    return sorted(missing)


def check_module(type: str, name: str, req: ModuleCheckRequest):
    """
    Actually run Metasploit's own `check` action against a target for one
    module - the same mechanism post/multi/recon/local_exploit_suggester
    uses internally - rather than trusting a name/description match from
    GET /modules/suggest. `check` is Metasploit's own safe/read-only probe
    convention (not an exploit attempt), but it still reaches out to the
    target, so this is opt-in per module rather than run automatically for
    every suggestion.
    """
    if type not in EXECUTABLE_TYPES:
        raise HTTPException(400, f"type must be one of {sorted(EXECUTABLE_TYPES)}")
    if not _module_path_is_valid(name):
        raise HTTPException(400, "Invalid module name.")
    for key in req.options:
        if not _CHECK_SETTABLE_KEY_RE.fullmatch(key):
            raise HTTPException(400, f"Invalid option name: {key}")

    # Preflight the module datastore before opening a console. A check run
    # with a missing required value can return an unhelpful "unknown" verdict;
    # surface the exact missing options instead of pretending the probe ran.
    try:
        declared_options = rpc.call("module.options", type, name)
    except MsfRpcError:
        declared_options = None
    missing_options = _missing_required_check_options(declared_options, req.options)
    if missing_options:
        return {
            "module": f"{type}/{name}",
            "verdict": "unknown",
            "raw_output": (
                "Check was not run. Required module options have no supplied value "
                f"or default: {', '.join(missing_options)}. Open the module and configure these options, then retry."
            ),
        }

    console_id: str | None = None
    try:
        created = rpc.call("console.create")
        console_raw_id = created.get("id") if isinstance(created, dict) else None
        if console_raw_id is None:
            raise HTTPException(502, "Metasploit did not provide a console for the check.")
        console_id = str(console_raw_id)
        try:
            rpc.call("console.read", console_id)
        except MsfRpcError:
            pass

        use_output = _run_console_command(console_id, f"use {type}/{name}")
        if re.search(r"(?i)(failed to load|could not load|invalid module|no module selected)", use_output):
            raise HTTPException(502, f"Metasploit could not select module '{type}/{name}'.")

        for key, value in req.options.items():
            safe_value = str(value).replace("\n", " ").replace("\r", " ").strip()
            if not safe_value:
                continue
            _run_console_command(console_id, f"set {key} {safe_value}")

        check_output = _run_console_command(console_id, "check", timeout_seconds=30.0)
        return {
            "module": f"{type}/{name}",
            "verdict": _check_verdict(check_output),
            "raw_output": check_output[-2000:].strip(),
        }
    except MsfRpcError as exc:
        raise HTTPException(502, f"Metasploit check failed: {exc}") from exc
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
