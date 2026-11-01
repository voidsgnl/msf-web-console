import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlsplit, urlunsplit

import requests
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/web-recon", tags=["web-recon"])

TOOL_CATALOG = [
    {"id":"httpx","name":"httpx","category":"HTTP probing","purpose":"Probe live web services and collect response metadata."},
    {"id":"whatweb","name":"WhatWeb","category":"Technology fingerprinting","purpose":"Identify web technologies and application frameworks."},
    {"id":"katana","name":"Katana","category":"Crawling","purpose":"Discover links, routes, and application endpoints."},
    {"id":"ffuf","name":"ffuf","category":"Content discovery","purpose":"Discover paths and virtual hosts using configured wordlists."},
    {"id":"gobuster","name":"Gobuster","category":"Content discovery","purpose":"Discover directories, files, DNS names, and virtual hosts."},
    {"id":"feroxbuster","name":"feroxbuster","category":"Content discovery","purpose":"Discover web content through recursive directory enumeration."},
    {"id":"nuclei","name":"Nuclei","category":"Vulnerability scanning","purpose":"Run selected template-based security checks."},
    {"id":"nikto","name":"Nikto","category":"Web server checks","purpose":"Check web servers for known issues and unsafe configuration."},
    {"id":"wpscan","name":"WPScan","category":"CMS assessment","purpose":"Assess WordPress core, themes, and plugins."},
    {"id":"subfinder","name":"Subfinder","category":"Subdomain discovery","purpose":"Discover subdomains from passive data sources."},
    {"id":"amass","name":"Amass","category":"Asset discovery","purpose":"Map domains and related attack-surface assets."},
    {"id":"testssl.sh","name":"testssl.sh","category":"TLS analysis","purpose":"Inspect TLS protocols, ciphers, and certificate configuration."},
    {"id":"nmap","name":"Nmap","category":"Network discovery","purpose":"Identify exposed ports and service details."},
]


class WebProbeRequest(BaseModel):
    assessment_id: int = Field(ge=1)
    url: str = Field(min_length=1, max_length=2048)
    authorized: bool = False


def _normalise_url(raw_url: str) -> str:
    value = raw_url.strip()
    if not value or any(char.isspace() for char in value):
        raise HTTPException(400, "Enter one valid HTTP or HTTPS URL.")
    if "://" not in value:
        value = "https://" + value
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError as exc:
        raise HTTPException(400, "The URL or port is invalid.") from exc
    if parsed.scheme.lower() not in {"http", "https"}:
        raise HTTPException(400, "Only HTTP and HTTPS targets are supported.")
    if not parsed.hostname or parsed.username or parsed.password:
        raise HTTPException(400, "Enter a hostname or IP without embedded credentials.")
    if parsed.fragment:
        raise HTTPException(400, "Remove the URL fragment.")
    return value


def _technology_hints(headers: dict[str, str], body: str) -> list[str]:
    combined = " ".join(headers.values()) + " " + body
    checks = [
        (r"wordpress|wp-content|wp-includes", "WordPress"),
        (r"drupal\.settings|/sites/default/", "Drupal"),
        (r"joomla|/media/system/js/", "Joomla"),
        (r"next\.js|__next", "Next.js"),
        (r"react|data-reactroot", "React"),
        (r"vue\.js|__vue__", "Vue.js"),
        (r"laravel", "Laravel"),
        (r"django", "Django"),
        (r"asp\.net|__viewstate", "ASP.NET"),
        (r"php", "PHP"),
    ]
    found = [name for pattern, name in checks if re.search(pattern, combined, re.IGNORECASE)]
    server = headers.get("server", "")
    for pattern, name in ((r"nginx", "Nginx"), (r"apache", "Apache"), (r"microsoft-iis", "Microsoft IIS"), (r"cloudflare", "Cloudflare")):
        if re.search(pattern, server, re.IGNORECASE) and name not in found:
            found.append(name)
    powered = headers.get("x-powered-by")
    if powered and powered not in found:
        found.append(powered[:100])
    return found


@router.get("/tools")
def list_tools():
    """Report local tool availability; never executes the tools."""
    tools = [{**item, "installed": (path := shutil.which(item["id"])) is not None, "path": path} for item in TOOL_CATALOG]
    return {"tools": tools, "built_in": [{"name":"HTTP response probe","available":True,"description":"One bounded HTTP GET; no crawling or vulnerability testing."}]}


@router.post("/probe")
def probe_web_service(req: WebProbeRequest):
    """Perform one bounded HTTP GET against a target explicitly confirmed as authorized."""
    if not req.authorized:
        raise HTTPException(400, "Confirm that you own this target or have explicit permission to assess it.")
    target_url = _normalise_url(req.url)
    from app.routes.assessments import assert_target_in_scope, record_tool_execution
    scope = assert_target_in_scope(req.assessment_id, target_url)
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    session = requests.Session()
    session.trust_env = False
    try:
        with session.get(target_url, headers={"User-Agent":"MSF-Web-Console-Recon/0.1","Accept":"text/html,application/xhtml+xml,*/*;q=0.8"}, timeout=(3.0,8.0), allow_redirects=False, stream=True, verify=True) as response:
            chunks = []
            total = 0
            for chunk in response.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                remaining = 65536 - total
                chunks.append(chunk[:remaining])
                total += min(len(chunk), remaining)
                if total >= 65536:
                    break
            body = b"".join(chunks).decode(response.encoding or "utf-8", errors="replace")
            headers = {key.lower():value[:300] for key,value in response.headers.items() if key.lower() in {"server","content-type","x-powered-by","x-generator","location","cf-ray","cf-cache-status","strict-transport-security"}}
            title_match = re.search(r"<title[^>]*>(.*?)</title\s*>", body, re.IGNORECASE | re.DOTALL)
            title = re.sub(r"\s+", " ", title_match.group(1)).strip()[:200] if title_match else None
            result = {"target":target_url,"status_code":response.status_code,"reason":response.reason,"final_url":response.url,"redirect_location":headers.get("location"),"title":title,"headers":headers,"technologies":_technology_hints(headers,body),"content_type":response.headers.get("Content-Type"),"body_truncated":total >= 65536,"bytes_inspected":total,"assessment":"HTTP response observed; this probe does not establish whether the application is vulnerable."}
            finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            execution = record_tool_execution(scope, "builtin-http-probe", target_url, started_at, finished_at, 0, total >= 65536, [result], "")
            result["execution_id"] = execution["id"]
            return result
    except requests.exceptions.SSLError as exc:
        raise HTTPException(502, f"TLS negotiation failed: {exc}") from exc
    except requests.exceptions.Timeout as exc:
        raise HTTPException(504, "The web service did not respond within 8 seconds.") from exc
    except requests.exceptions.RequestException as exc:
        raise HTTPException(502, f"HTTP probe failed: {exc}") from exc
    finally:
        session.close()


# Only these fixed adapters are executable from the UI. Arguments are built
# here (never accepted from the browser), and subprocesses never use a shell.
RUNNABLE_TOOLS = {
    "httpx": {"name": "httpx", "timeout": 30, "max_output": 262144},
    "whatweb": {"name": "WhatWeb", "timeout": 45, "max_output": 262144},
    # Passive sources only; no active DNS or HTTP probing.
    "subfinder": {"name": "Subfinder (passive)", "timeout": 150, "max_output": 1048576},
    "katana": {"name": "Katana (controlled crawl)", "timeout": 120, "max_output": 1048576},
}


class ToolRunRequest(BaseModel):
    assessment_id: int = Field(ge=1)
    tool_id: str = Field(pattern=r"^(httpx|whatweb|subfinder|katana)$")
    url: str = Field(min_length=1, max_length=2048)
    authorized: bool = False


def _build_tool_command(tool_id: str, executable: str, target_url: str) -> list[str]:
    if tool_id == "httpx":
        return [
            executable, "-json", "-silent", "-no-color", "-no-stdin", "-nfs",
            "-timeout", "10", "-retries", "0", "-rstr", "1048576", "-u", target_url,
        ]
    if tool_id == "whatweb":
        return [
            executable, "--log-json=/dev/stdout", "--quiet", "--no-errors", "--color=never",
            "--max-threads=1", "--follow-redirect=never", "--max-redirects=0", "--wait=1", "--open-timeout=5", "--read-timeout=10", target_url,
        ]
    if tool_id == "subfinder":
        hostname = (urlsplit(target_url).hostname or "").lower()
        if not hostname:
            raise HTTPException(400, "A valid approved hostname is required for passive subdomain discovery.")
        return [executable, "-d", hostname, "-silent", "-json", "-cs", "-duc", "-mr", "100", "-timeout", "10", "-max-time", "2", "-rl", "5"]
    if tool_id == "katana":
        parsed = urlsplit(target_url)
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            raise HTTPException(400, "A valid approved hostname is required for crawling.")
        host_literal = "[" + hostname + "]" if ":" in hostname else hostname
        default_port = 443 if parsed.scheme.lower() == "https" else 80
        if parsed.port and parsed.port != default_port:
            authority_pattern = re.escape(host_literal + ":" + str(parsed.port))
        else:
            authority_pattern = re.escape(host_literal) + (r"(:%s)?" % default_port if parsed.port in {None, default_port} else "")
        scope_pattern = "^" + re.escape(parsed.scheme.lower()) + "://" + authority_pattern + r"(/|$)"
        return [
            executable, "-u", target_url, "-silent", "-nc", "-j", "-duc", "-or", "-ob",
            "-d", "3", "-jc", "-iqp", "-mdp", "100", "-ct", "90s", "-mrs", "1048576",
            "-timeout", "8", "-retry", "0", "-rl", "2", "-c", "1", "-p", "1",
            # Keep crawler redirects disabled. The adapter resolves only same-origin
            # redirects from the explicitly approved entry URL before starting Katana.
            # Do not use -ns: it disables Katana's default host scope.
            "-dr", "-fr", r"(%5[cC]|\\)", "-cs", scope_pattern,
        ]
    raise HTTPException(400, "This reconnaissance tool is not enabled for execution.")


def _parse_tool_output(tool_id: str, output: str) -> list[dict]:
    import json

    def normalise(item: object) -> dict:
        if tool_id == "httpx" and isinstance(item, dict):
            return {"url": item.get("url"), "status_code": item.get("status_code"), "title": item.get("title"), "webserver": item.get("webserver"), "content_type": item.get("content_type"), "technologies": item.get("tech") if isinstance(item.get("tech"), list) else [], "host": item.get("host"), "raw": None}
        if tool_id == "whatweb" and isinstance(item, dict):
            plugins = item.get("plugins") if isinstance(item.get("plugins"), dict) else {}
            title_plugin = plugins.get("title", {})
            title_values = title_plugin.get("string") if isinstance(title_plugin, dict) else None
            title = title_values[0] if isinstance(title_values, list) and title_values else (title_values if isinstance(title_values, str) else None)
            return {"target": item.get("target"), "http_status": item.get("http_status"), "title": title, "technologies": sorted(plugins.keys()), "raw": None}
        if tool_id == "subfinder" and isinstance(item, dict):
            host = item.get("host")
            if not isinstance(host, str):
                host = item.get("input")
            sources = item.get("sources") if isinstance(item.get("sources"), list) else []
            return {"host": host.lower().rstrip(".") if isinstance(host, str) else None,
                    "sources": [str(source)[:100] for source in sources[:20]], "raw": None}
        if tool_id == "katana" and isinstance(item, dict):
            request = item.get("request") if isinstance(item.get("request"), dict) else {}
            response = item.get("response") if isinstance(item.get("response"), dict) else {}
            endpoint = item.get("endpoint") or item.get("url") or request.get("endpoint") or request.get("url")
            response_headers = response.get("headers") if isinstance(response.get("headers"), dict) else {}
            location = next(
                (value for key, value in response_headers.items() if str(key).lower().replace("-", "_") == "location"),
                None,
            )
            content_type = next(
                (value for key, value in response_headers.items() if str(key).lower().replace("-", "_") == "content_type"),
                None,
            )
            status_code = response.get("status_code", item.get("status_code"))
            return {
                "url": endpoint if isinstance(endpoint, str) else None,
                "method": str(request.get("method") or item.get("method") or "GET")[:12],
                "status_code": status_code,
                "content_type": str(content_type)[:200] if isinstance(content_type, str) else None,
                "redirect_location": str(location)[:2048] if isinstance(location, str) else None,
                "source": str(request.get("source") or item.get("source") or "")[:500],
                "tag": str(request.get("tag") or item.get("tag") or "")[:100],
                "attribute": str(request.get("attribute") or item.get("attribute") or "")[:100],
                "raw": None,
            }
        return {"raw": str(item)[:4000]}

    # WhatWeb writes one JSON array; httpx emits newline-delimited JSON.
    try:
        document = json.loads(output)
        if isinstance(document, list):
            return [normalise(item) for item in document]
        if isinstance(document, dict) and tool_id in {"whatweb", "subfinder", "katana"}:
            return [normalise(document)]
    except (TypeError, ValueError):
        pass

    records: list[dict] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(normalise(json.loads(line)))
        except (TypeError, ValueError):
            if tool_id == "katana":
                # The bounded stdout read can end in the middle of a JSON
                # record. Do not persist that partial response as evidence.
                continue
            records.append({"raw": line[:4000]})
    return records


def _origin_key(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    return (
        scheme,
        (parsed.hostname or "").lower(),
        parsed.port or (443 if scheme == "https" else 80),
    )


def _resolve_same_origin_redirects(target_url: str, max_redirects: int = 5) -> tuple[str, list[dict], dict | None]:
    """Resolve only entry-point redirects that remain on the approved origin."""
    session = requests.Session()
    session.trust_env = False
    current_url = target_url
    chain: list[dict] = []
    redirect_statuses = {301, 302, 303, 307, 308}
    try:
        for _ in range(max_redirects + 1):
            try:
                with session.get(
                    current_url,
                    headers={"User-Agent": "MSF-Web-Console-Recon/0.1", "Accept": "*/*"},
                    timeout=(3.0, 8.0),
                    allow_redirects=False,
                    stream=True,
                    verify=True,
                ) as response:
                    location = response.headers.get("Location")
                    if response.status_code not in redirect_statuses or not location:
                        return current_url, chain, None
                    destination = urljoin(current_url, location)
                    try:
                        destination = _normalise_url(destination)
                    except HTTPException:
                        blocked = {
                            "from": current_url, "status_code": response.status_code,
                            "location": str(location)[:2048], "followed": False,
                            "reason": "Redirect destination is not a valid HTTP(S) URL.",
                        }
                        return current_url, chain + [blocked], blocked
                    redirect = {
                        "from": current_url, "status_code": response.status_code,
                        "to": destination, "followed": False,
                    }
                    if len(chain) >= max_redirects:
                        redirect["reason"] = f"Stopped after the maximum of {max_redirects} same-origin redirects."
                        return current_url, chain + [redirect], redirect
                    if _origin_key(destination) != _origin_key(target_url):
                        redirect["reason"] = "Destination is outside the approved scheme/host/port."
                        return current_url, chain + [redirect], redirect
                    redirect["followed"] = True
                    chain.append(redirect)
                    current_url = destination
            except requests.exceptions.RequestException as exc:
                return current_url, chain, {
                    "error": f"Redirect preflight could not complete: {type(exc).__name__}.",
                }
        return current_url, chain, {
            "error": f"Stopped after the maximum of {max_redirects} same-origin redirects.",
        }
    finally:
        session.close()


def _filter_katana_records(records: list[dict], target_url: str) -> list[dict]:
    """Retain safe HTTP(S) discoveries on the exact approved origin."""
    approved = urlsplit(target_url)
    approved_origin = (approved.scheme.lower(), (approved.hostname or "").lower(), approved.port or (443 if approved.scheme.lower() == "https" else 80))
    scoped_records = []
    for record in records:
        if record.get("kind") == "redirect_chain":
            scoped_records.append(record)
            continue
        endpoint = record.get("url")
        if not isinstance(endpoint, str) or len(endpoint) > 2048 or any(ch.isspace() for ch in endpoint):
            continue
        try:
            parsed_endpoint = urlsplit(endpoint)
            endpoint_port = parsed_endpoint.port or (443 if parsed_endpoint.scheme.lower() == "https" else 80)
            endpoint_origin = (parsed_endpoint.scheme.lower(), (parsed_endpoint.hostname or "").lower(), endpoint_port)
        except ValueError:
            continue
        if (parsed_endpoint.scheme.lower() in {"http", "https"} and parsed_endpoint.hostname and not parsed_endpoint.username and not parsed_endpoint.password and not parsed_endpoint.fragment and endpoint_origin == approved_origin):
            scoped_records.append(record)
    return scoped_records


def _classify_katana_records(records: list[dict]) -> list[dict]:
    """Classify and deduplicate discoveries without discarding useful evidence."""
    static_extensions = {".7z", ".avif", ".css", ".csv", ".eot", ".gif", ".gz", ".ico", ".jpeg", ".jpg", ".js", ".map", ".mp3", ".mp4", ".otf", ".pdf", ".png", ".svg", ".tar", ".ttf", ".webm", ".webp", ".woff", ".woff2", ".zip"}
    api_path = re.compile(r"(?:^|/)(?:api|graphql|rest|v[0-9]+)(?:/|$)", re.IGNORECASE)
    next_static_path = re.compile(r"^/_next/static(?:/|$)", re.IGNORECASE)
    next_image_path = re.compile(r"^/_next/image$", re.IGNORECASE)
    deduplicated: dict[tuple[str, str], dict] = {}
    output: list[dict] = []
    for record in records:
        if record.get("kind") == "redirect_chain":
            output.append(record)
            continue
        endpoint = record.get("url")
        if not isinstance(endpoint, str):
            output.append(record)
            continue
        parsed = urlsplit(endpoint)
        path = parsed.path or "/"
        filename = path.rsplit("/", 1)[-1]
        suffix = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        status = record.get("status_code")
        location = record.get("redirect_location")
        script_text = (
            str(record.get("tag") or "").lower() == "script"
            and str(record.get("attribute") or "").lower() == "text"
        )
        malformed = "\\" in path or bool(re.search(r"%5c", path, re.IGNORECASE))
        query = parse_qs(parsed.query)
        next_image_asset = bool(next_image_path.fullmatch(path))
        next_image_source = query.get("url", [""])[0]
        next_image_suffix = Path(next_image_source).suffix.lower() if next_image_source else ""
        if malformed:
            resource_type, reason = "malformed", "Path contains a raw or percent-encoded backslash."
            if script_text:
                reason += " Candidate came from script text and is retained only as evidence."
        elif next_image_asset or next_static_path.match(path):
            resource_type = "static_asset"
            reason = (
                "Next.js image optimization route identified as a static asset"
                + (f" for {next_image_suffix} source." if next_image_suffix in static_extensions else ".")
                if next_image_asset
                else "Next.js framework static resource identified by path."
            )
        elif (isinstance(status, int) and 300 <= status < 400) or location:
            resource_type, reason = "redirect", "HTTP redirect observed; page redirects are not followed during crawling."
            if path.lower().startswith("/_next/"):
                resource_type, reason = "framework_redirect", "Next.js framework redirect observed; crawler redirects are not followed."
        elif suffix in static_extensions or str(record.get("content_type") or "").split(";", 1)[0].strip().lower().startswith(("image/", "font/", "audio/", "video/", "text/css", "application/javascript", "text/javascript")):
            resource_type, reason = "static_asset", "Response content type or URL extension identifies a static resource."
        elif api_path.search(path):
            resource_type, reason = "api_candidate", "Path resembles an API route; this is a hint, not proof of an API."
        else:
            resource_type, reason = "page", "Same-origin application route discovered by the crawler."
            if script_text:
                reason = "Application route candidate extracted from script text."
        scheme, host = parsed.scheme.lower(), (parsed.hostname or "").lower()
        default_port = 443 if scheme == "https" else 80
        authority = ("[" + host + "]") if ":" in host else host
        if parsed.port and parsed.port != default_port:
            authority += ":" + str(parsed.port)
        canonical = urlunsplit((scheme, authority, parsed.path or "/", parsed.query, ""))
        record.update({"canonical_url": canonical, "endpoint_group": path, "resource_type": resource_type, "classification_reason": reason, "fetch_state": "fetched" if isinstance(status, int) else "discovered_unverified", "display_default": resource_type not in {"static_asset", "malformed", "framework_redirect"}})
        key = (str(record.get("method") or "GET").upper(), canonical)
        if key in deduplicated:
            existing = deduplicated[key]
            existing["observations"] = existing.get("observations", 1) + 1
            if existing.get("status_code") is None and status is not None:
                existing["status_code"], existing["fetch_state"] = status, "fetched"
            continue
        record["observations"] = 1
        deduplicated[key] = record
        output.append(record)
    return output

@router.post("/run")
def run_recon_tool(req: ToolRunRequest):
    """Run one fixed, bounded HTTP reconnaissance adapter against one authorized URL."""
    import os
    import subprocess
    import tempfile

    if not req.authorized:
        raise HTTPException(400, "Confirm that you own this target or have explicit permission to assess it.")
    target_url = _normalise_url(req.url)
    from app.routes.assessments import assert_target_in_scope, record_tool_execution
    scope = assert_target_in_scope(req.assessment_id, target_url)
    config = RUNNABLE_TOOLS.get(req.tool_id)
    if not config:
        raise HTTPException(400, "This reconnaissance tool is not enabled for execution.")
    executable = shutil.which(req.tool_id)
    if not executable:
        raise HTTPException(409, f"{config['name']} is not installed or is not available on the backend PATH.")
    crawl_target = target_url
    redirect_chain: list[dict] = []
    redirect_note: dict | None = None
    if req.tool_id == "katana":
        crawl_target, redirect_chain, redirect_note = _resolve_same_origin_redirects(target_url)
    command = _build_tool_command(req.tool_id, executable, crawl_target)
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        with tempfile.TemporaryFile(mode="w+t", encoding="utf-8", errors="replace") as stdout_file, tempfile.TemporaryFile(mode="w+t", encoding="utf-8", errors="replace") as stderr_file:
            completed = subprocess.run(
                command,
                stdout=stdout_file,
                stderr=stderr_file,
                timeout=config["timeout"],
                check=False,
                shell=False,
                stdin=subprocess.DEVNULL,
                env={
                    "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                    "HOME": os.path.expanduser("~"),
                    "LANG": os.environ.get("LANG", "C.UTF-8"),
                    "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
                },
            )
            stdout_file.seek(0, 2)
            output_size = stdout_file.tell()
            stdout_file.seek(0)
            stdout = stdout_file.read(config["max_output"])
            stderr_file.seek(0)
            stderr = stderr_file.read(4000)
    except subprocess.TimeoutExpired as exc:
        finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        record_tool_execution(
            scope, req.tool_id, target_url, started_at, finished_at,
            124, False, [], f"Timed out after {config['timeout']} seconds.",
        )
        raise HTTPException(504, f"{config['name']} exceeded its {config['timeout']}-second time limit.") from exc
    except OSError as exc:
        finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        record_tool_execution(
            scope, req.tool_id, target_url, started_at, finished_at,
            127, False, [], exc.strerror or "Execution error.",
        )
        raise HTTPException(502, f"{config['name']} could not be started: {exc.strerror or 'execution error'}.") from exc

    finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    records = _parse_tool_output(req.tool_id, stdout)
    if req.tool_id == "katana":
        records = _filter_katana_records(records, target_url)
        records = _classify_katana_records(records)
        if redirect_chain:
            records.append({"kind": "redirect_chain", "redirects": redirect_chain})
    execution = record_tool_execution(
        scope, req.tool_id, target_url, started_at, finished_at,
        completed.returncode, output_size > config["max_output"], records, stderr,
    )

    return {
        "execution_id": execution["id"],
        "assessment_id": req.assessment_id,
        "tool_id": req.tool_id,
        "tool": config["name"],
        "target": target_url,
        "exit_code": completed.returncode,
        "timed_out": False,
        "output_truncated": output_size > config["max_output"],
        "records": records,
        "redirect_chain": redirect_chain if req.tool_id == "katana" else [],
        "stderr": stderr,
        "assessment": (
            "Subfinder uses passive data sources only. Discovered hostnames are inventory leads, "
            "not approved targets; this adapter does not initiate DNS probes or HTTP requests."
            if req.tool_id == "subfinder"
            else (
                "Katana used a shallow, time- and page-bounded crawl restricted to the approved "
                "scheme/host/port. The entry URL was preflighted and only same-origin redirects "
                "were followed; crawler-discovered page redirects remain disabled. Cross-origin "
                "redirects are not followed, and discovered URLs do not expand approved scope."
                + (f" Redirect note: {redirect_note.get('reason') or redirect_note.get('error')}" if redirect_note else "")
                if req.tool_id == "katana"
                else "Tool output is reconnaissance evidence, not a confirmed vulnerability verdict."
            )
        ),
    }
