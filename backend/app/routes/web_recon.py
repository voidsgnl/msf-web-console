import re
import shutil
from datetime import datetime, timezone
from urllib.parse import urlsplit

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
    "httpx": {
        "name": "httpx",
        "timeout": 30,
        "max_output": 262144,
    },
    "whatweb": {
        "name": "WhatWeb",
        "timeout": 45,
        "max_output": 262144,
    },
}


class ToolRunRequest(BaseModel):
    assessment_id: int = Field(ge=1)
    tool_id: str = Field(pattern=r"^(httpx|whatweb)$")
    url: str = Field(min_length=1, max_length=2048)
    authorized: bool = False


def _build_tool_command(tool_id: str, executable: str, target_url: str) -> list[str]:
    if tool_id == "httpx":
        return [
            executable, "-u", target_url, "-json", "-silent", "-no-color", "-no-stdin", "-nfs",
            "-timeout", "10", "-retries", "0", "-rstr", "1048576",
        ]
    if tool_id == "whatweb":
        return [
            executable, "--log-json=/dev/stdout", "--quiet", "--no-errors", "--color=never",
            "--max-threads=1", "--max-redirects=0", "--wait=1", "--open-timeout=5", "--read-timeout=10", target_url,
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
        return {"raw": str(item)[:4000]}

    # WhatWeb writes one JSON array; httpx emits newline-delimited JSON.
    try:
        document = json.loads(output)
        if isinstance(document, list):
            return [normalise(item) for item in document]
        if isinstance(document, dict) and tool_id == "whatweb":
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
            records.append({"raw": line[:4000]})
    return records


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
    command = _build_tool_command(req.tool_id, executable, target_url)
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
        "stderr": stderr,
        "assessment": "Tool output is reconnaissance evidence, not a confirmed vulnerability verdict.",
    }
