import hashlib
import os
import re
import uuid
import shutil
from concurrent.futures import ThreadPoolExecutor
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
    {"id":"gobuster","name":"Gobuster","category":"Content discovery","purpose":"Enumerate web directories and files using a selected wordlist."},
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
    "gobuster": {"name": "Gobuster (directory enumeration)", "timeout": 180, "max_output": 1048576},
}


class ToolRunRequest(BaseModel):
    assessment_id: int = Field(ge=1)
    tool_id: str = Field(pattern=r"^(httpx|whatweb|subfinder|katana|gobuster)$")
    url: str = Field(min_length=1, max_length=2048)
    authorized: bool = False
    wordlist_id: str | None = Field(default=None, max_length=512)
    extensions: str = Field(default="", max_length=120)



def _project_wordlist_root() -> Path:
    """Return the repository-local directory for untracked wordlist datasets."""
    return Path(__file__).resolve().parents[3] / "wordlists"


def _wordlist_roots() -> list[Path]:
    configured = os.environ.get("MSF_WEB_WORDLIST_DIRS")
    # Explicit directories are searched first, but they extend rather than
    # replace the repository-local and standard system wordlist locations.
    values = (configured.split(os.pathsep) if configured else []) + [
        str(_project_wordlist_root()),
        "/usr/share/seclists/Discovery/Web-Content",
        "/usr/share/wordlists",
        "/usr/share/dirb/wordlists",
        "/usr/share/dirbuster/wordlists",
    ]
    roots: list[Path] = []
    for value in values:
        if not value.strip():
            continue
        try:
            resolved = Path(value).expanduser().resolve(strict=True)
        except OSError:
            continue
        if resolved.is_dir() and resolved not in roots:
            roots.append(resolved)
    return roots


def _list_wordlists() -> list[dict]:
    """Expose bounded wordlist choices without exposing arbitrary filesystem access."""
    allowed_suffixes = {".txt", ".lst", ".wordlist"}
    results: list[dict] = []
    for root_index, root in enumerate(_wordlist_roots()):
        for current, directories, filenames in os.walk(root, followlinks=False):
            current_path = Path(current)
            depth = len(current_path.relative_to(root).parts)
            # SecLists commonly nests Web-Content at
            # SecLists/Discovery/Web-Content (three levels below the root).
            # Allow a bounded depth so those lists are actually selectable.
            directories[:] = [name for name in directories if not (current_path / name).is_symlink()] if depth < 5 else []
            for filename in filenames:
                candidate = current_path / filename
                if candidate.suffix.lower() not in allowed_suffixes or candidate.is_symlink():
                    continue
                try:
                    resolved = candidate.resolve(strict=True)
                    size = resolved.stat().st_size
                except OSError:
                    continue
                if not resolved.is_file() or not resolved.is_relative_to(root) or size <= 0 or size > 64 * 1024 * 1024:
                    continue
                results.append({"id": f"{root_index}:{candidate.relative_to(root).as_posix()}", "name": candidate.relative_to(root).as_posix(), "size_bytes": size})
                if len(results) >= 100:
                    return sorted(results, key=lambda item: item["name"].lower())
    return sorted(results, key=lambda item: item["name"].lower())


def _resolve_wordlist(wordlist_id: str) -> Path:
    try:
        root_index_text, relative_text = wordlist_id.split(":", 1)
        root_index = int(root_index_text)
        relative = Path(relative_text)
    except (ValueError, AttributeError):
        raise HTTPException(400, "Select a valid backend wordlist.") from None
    roots = _wordlist_roots()
    if root_index < 0 or root_index >= len(roots) or relative.is_absolute() or ".." in relative.parts:
        raise HTTPException(400, "Select a valid backend wordlist.")
    root = roots[root_index]
    candidate = root / relative
    try:
        resolved = candidate.resolve(strict=True)
        size = resolved.stat().st_size
    except OSError:
        raise HTTPException(400, "The selected wordlist is no longer available.") from None
    if not resolved.is_file() or not resolved.is_relative_to(root) or candidate.is_symlink():
        raise HTTPException(400, "The selected wordlist is outside the configured wordlist directories.")
    if resolved.suffix.lower() not in {".txt", ".lst", ".wordlist"} or size <= 0 or size > 64 * 1024 * 1024:
        raise HTTPException(400, "The selected wordlist must be a non-empty text list no larger than 64 MiB.")
    return resolved


def _normalise_gobuster_extensions(value: str) -> str:
    extensions = [item.strip().lower().lstrip(".") for item in value.split(",") if item.strip()]
    if len(extensions) > 10 or any(not re.fullmatch(r"[a-z0-9]{1,10}", item) for item in extensions):
        raise HTTPException(400, "Extensions must be up to 10 comma-separated alphanumeric suffixes.")
    return ",".join(dict.fromkeys(extensions))


@router.get("/wordlists")
def list_wordlists():
    return {"wordlists": _list_wordlists()}


def _build_tool_command(
    tool_id: str,
    executable: str,
    target_url: str,
    wordlist_path: str | None = None,
    extensions: str = "",
    gobuster_exclude_length: int | str | None = None,
) -> list[str]:
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
    if tool_id == "gobuster":
        if not wordlist_path:
            raise HTTPException(400, "Select an available backend wordlist before running Gobuster.")
        command = [
            executable, "dir", "-u", target_url, "-w", wordlist_path,
            "-t", "2", "--delay", "500ms", "--timeout", "8s",
            "--no-progress", "--quiet", "--no-error", "--no-color",
            "-e",
            "-s", "200,204,301,302,307,401,403",
            # Gobuster defaults to a 404 blacklist; clear it when using an allowlist.
            "--status-codes-blacklist", "",
        ]
        if gobuster_exclude_length is not None:
            command.extend(["--exclude-length", str(gobuster_exclude_length)])
        if extensions:
            command.extend(["-x", extensions])
        return command
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
            # Use crawl-out-scope to reject malformed candidates before fetching them.
            # Keep filter-regex as defense-in-depth for any malformed URLs emitted by
            # discovery paths that do not pass through the crawl scope.
            "-dr", "-cos", r"(%5[cC]|\\)", "-fr", r"(%5[cC]|\\)", "-cs", scope_pattern,
        ]
    raise HTTPException(400, "This reconnaissance tool is not enabled for execution.")


def _gobuster_body_signature(body: bytes, encoding: str | None = None) -> dict:
    """Create a stable signature and token-shingle set for a response body."""
    text = body.decode(encoding if isinstance(encoding, str) else "utf-8", errors="replace")
    text = re.sub(
        r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        "<dynamic-uuid>",
        text,
    )
    text = re.sub(
        r"\b20\d{2}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b",
        "<dynamic-time>",
        text,
    )
    text = re.sub(
    text = re.sub(
        r"""(?is)(<input\b[^>]*(?:name|id)=["'](?:csrf|csrf_token|nonce|authenticity_token|requestverificationtoken)["'][^>]*value=["'])[^"']+(["'])""",
        r"\1<dynamic-token>\2",
        text,
    )
        r"(?i)(csrf(?:token)?|nonce|authenticity_token|requestverificationtoken)([\s:=\"']+)[a-z0-9._~-]{8,}",
        r"\1\2<dynamic-token>",
        text,
    )
    normalised = re.sub(r"\s+", " ", text).strip().lower()
    tokens = re.findall(r"[a-z0-9][a-z0-9_./:-]{2,}", normalised)
    if len(tokens) >= 3:
        shingles = {" ".join(tokens[index:index + 3]) for index in range(len(tokens) - 2)}
    else:
        shingles = set(tokens)
    return {
        "fingerprint": hashlib.sha256(normalised.encode("utf-8")).hexdigest(),
        "shingles": shingles,
        "normalised_length": len(normalised),
    }


def _gobuster_body_similarity(left: dict, right: dict) -> float:
    left_shingles = left.get("shingles") or set()
    right_shingles = right.get("shingles") or set()
    if not left_shingles or not right_shingles:
        return 1.0 if left.get("fingerprint") == right.get("fingerprint") else 0.0
    union = left_shingles | right_shingles
    return len(left_shingles & right_shingles) / len(union) if union else 0.0


def _fetch_gobuster_candidate_body(url: str) -> tuple[int, dict] | None:
    """Re-fetch one same-origin candidate without following redirects."""
    session = requests.Session()
    session.trust_env = False
    try:
        with session.get(
            url,
            headers={"User-Agent": "gobuster/3.8.2", "Accept": "*/*"},
            timeout=(3.0, 5.0),
            allow_redirects=False,
            stream=True,
            verify=True,
        ) as response:
            body = bytearray()
            for chunk in response.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                body.extend(chunk)
                if len(body) > 1048576:
                    return None
            return response.status_code, _gobuster_body_signature(bytes(body), response.encoding)
    except requests.exceptions.RequestException:
        return None
    finally:
        session.close()


def _probe_gobuster_wildcard_length(target_url: str) -> dict:
    """Measure wildcard response sizes for random missing paths before enumeration."""
    session = requests.Session()
    session.trust_env = False
    lengths: set[int] = set()
    statuses: set[int] = set()
    body_signatures: list[dict] = []
    try:
        for _ in range(5):
            probe_url = urljoin(target_url.rstrip("/") + "/", str(uuid.uuid4()))
            try:
                with session.get(
                    probe_url,
                    headers={"User-Agent": "gobuster/3.8.2", "Accept": "*/*"},
                    timeout=(3.0, 8.0),
                    allow_redirects=False,
                    stream=True,
                    verify=True,
                ) as response:
                    statuses.add(response.status_code)
                    total = 0
                    body = bytearray()
                    for chunk in response.iter_content(chunk_size=8192):
                        if not chunk:
                            continue
                        total += len(chunk)
                        body.extend(chunk)
                        if total > 1048576:
                            raise HTTPException(502, "Gobuster wildcard probe response exceeded the 1 MiB inspection limit.")
                    # Measure decoded body bytes, matching Gobuster's response-size
                    # value even when the server uses gzip or another encoding.
                    lengths.add(total)
                    body_signatures.append({
                        "status_code": response.status_code,
                        **_gobuster_body_signature(bytes(body), response.encoding),
                    })
            except requests.exceptions.SSLError as exc:
                raise HTTPException(502, f"Gobuster wildcard probe TLS negotiation failed: {exc}") from exc
            except requests.exceptions.Timeout as exc:
                raise HTTPException(504, "Gobuster wildcard probe exceeded the 8-second timeout.") from exc
            except requests.exceptions.RequestException as exc:
                raise HTTPException(502, f"Gobuster wildcard probe failed: {exc}") from exc
        if not lengths:
            raise HTTPException(502, "Gobuster wildcard probe returned no response body.")
        values = sorted(lengths)
        reference_length = values[len(values) // 2]
        exclude_length: int | str
        if len(values) == 1:
            exclude_length = values[0]
        else:
            # Gobuster supports inclusive length ranges. This avoids missing a
            # transient wildcard size between two probe observations.
            exclude_length = f"{values[0]}-{values[-1]}"
        return {
            "exclude_length": exclude_length,
            "status_codes": sorted(statuses),
            "min_length": values[0],
            "max_length": values[-1],
            "reference_length": reference_length,
            # Classification is deliberately conservative: size proximity is
            # a signal for review, not proof that a path does not exist.
            "length_tolerance": max(128, round(reference_length * 0.01)),
            "body_signatures": body_signatures,
        }
    finally:
        session.close()


def _parse_gobuster_output(output: str, target_url: str) -> list[dict]:
    records: list[dict] = []
    legacy = re.compile(r"^(?P<path>\S+)\s+\(Status:\s*(?P<status>\d{3})\)(?:\s+\[Size:\s*(?P<size>\d+)\])?")
    modern = re.compile(r"^\[Status:\s*(?P<status>\d{3}),\s*Size:\s*(?P<size>\d+)[^]]*\]\s+(?P<path>\S+)")
    parsed_target = urlsplit(target_url)
    base = urlunsplit((parsed_target.scheme, parsed_target.netloc, (parsed_target.path or "/").rstrip("/") + "/", "", ""))
    approved_origin = _origin_key(target_url)
    for line in output.splitlines():
        value = line.strip()
        if not value:
            continue
        match = legacy.match(value) or modern.match(value)
        if not match:
            continue
        candidate = urljoin(base, match.group("path"))
        try:
            parsed = urlsplit(candidate)
            if (
                _origin_key(candidate) != approved_origin
                or parsed.username or parsed.password or parsed.fragment
            ):
                continue
        except ValueError:
            continue
        size_value = match.groupdict().get("size")
        records.append({
            "url": candidate, "path": parsed.path or "/",
            "status_code": int(match.group("status")),
            "content_length": int(size_value) if size_value else None,
            "discovery_type": "directory" if (parsed.path or "").endswith("/") else "path",
            "source": "gobuster",
        })
    deduplicated: dict[str, dict] = {}
    for record in records:
        if record["url"] in deduplicated:
            deduplicated[record["url"]]["observations"] += 1
        else:
            record["observations"] = 1
            deduplicated[record["url"]] = record
    return list(deduplicated.values())


def _classify_gobuster_records(records: list[dict], wildcard_profile: dict, target_url: str) -> dict:
    """Compare near-baseline responses with normalized body fingerprints."""
    baseline_statuses = set(wildcard_profile.get("status_codes", []))
    baseline_signatures = wildcard_profile.get("body_signatures", [])
    reference_length = int(wildcard_profile.get("reference_length", 0))
    tolerance = int(wildcard_profile.get("length_tolerance", 128))
    similarity_threshold = 0.92
    max_fingerprint_checks = 100
    approved_origin = _origin_key(target_url)
    candidates = []
    for record in records:
        status = record.get("status_code")
        length = record.get("content_length")
        if (
            isinstance(status, int)
            and status in baseline_statuses
            and isinstance(length, int)
            and abs(length - reference_length) <= tolerance
        ):
            try:
                if _origin_key(record.get("url", "")) == approved_origin:
                    candidates.append(record)
                else:
                    record["response_classification"] = "unverified"
                    record["classification_reason"] = "Candidate URL did not match the approved origin; no follow-up request was made."
            except (TypeError, ValueError):
                record["response_classification"] = "unverified"
                record["classification_reason"] = "Candidate URL could not be validated against the approved origin."
    checkable = candidates[:max_fingerprint_checks]
    with ThreadPoolExecutor(max_workers=2) as executor:
        fetched = list(executor.map(
            _fetch_gobuster_candidate_body,
            [record["url"] for record in checkable],
        ))
    fetched_by_url = {
        record["url"]: result for record, result in zip(checkable, fetched)
    }

    suspected = 0
    distinct = 0
    unverified = 0
    fingerprint_checks = 0
    for record in records:
        status = record.get("status_code")
        length = record.get("content_length")
        if record.get("response_classification") == "unverified":
            unverified += 1
        elif (
            isinstance(status, int)
            and status in baseline_statuses
            and isinstance(length, int)
            and abs(length - reference_length) <= tolerance
        ):
            result = fetched_by_url.get(record.get("url"))
            if result is None:
                record["response_classification"] = "unverified"
                record["classification_reason"] = (
                    "Response body could not be safely re-fetched for fingerprint comparison "
                    "(request failed, exceeded 1 MiB, or fingerprint-check limit reached)."
                )
                unverified += 1
                continue
            response_status, signature = result
            fingerprint_checks += 1
            comparable = [
                item for item in baseline_signatures
                if item.get("status_code") == response_status
            ]
            if not comparable or response_status != status:
                record["response_classification"] = "unverified"
                record["classification_reason"] = (
                    "The re-fetched response status did not match a usable random-path body baseline; "
                    "the path was retained without a wildcard verdict."
                )
                unverified += 1
                continue
            similarity = max(
                _gobuster_body_similarity(signature, item)
                for item in comparable
            )
            record["body_similarity"] = round(similarity, 4)
            if similarity >= similarity_threshold:
                record["response_classification"] = "suspected_wildcard"
                record["classification_reason"] = (
                    f"Normalized response body matches a random-path baseline "
                    f"({similarity:.1%} similarity; HTTP {status}; {length:,} bytes). "
                    "Review before treating this as a real path."
                )
                suspected += 1
            else:
                record["response_classification"] = "distinct_response"
                record["classification_reason"] = (
                    f"Response body differs from the random-path baseline "
                    f"({similarity:.1%} similarity; threshold {similarity_threshold:.0%}). "
                    "This is a distinct response, not proof that the path is valid."
                )
                distinct += 1
        elif isinstance(status, int) and isinstance(length, int):
            record["response_classification"] = "distinct_response"
            record["classification_reason"] = (
                "Status or response size differs from the random-path baseline; "
                "this is a distinct response, not proof that the path is valid."
            )
            distinct += 1
        else:
            record["response_classification"] = "unverified"
            record["classification_reason"] = (
                "Gobuster did not provide enough response metadata to compare this path with the wildcard baseline."
            )
            unverified += 1
    return {
        "baseline_status_codes": sorted(baseline_statuses),
        "baseline_length_range": [
            wildcard_profile.get("min_length"),
            wildcard_profile.get("max_length"),
        ],
        "reference_length": reference_length,
        "length_tolerance": tolerance,
        "body_similarity_threshold": similarity_threshold,
        "body_fingerprint_checks": fingerprint_checks,
        "body_fingerprint_check_limit": max_fingerprint_checks,
        "suspected_wildcard": suspected,
        "distinct_response": distinct,
        "unverified": unverified,
        "total": len(records),
    }

def _parse_tool_output(tool_id: str, output: str, target_url: str | None = None) -> list[dict]:
    import json
    if tool_id == "gobuster":
        return _parse_gobuster_output(output, target_url or "")

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
    wordlist_path: str | None = None
    gobuster_extensions = ""
    if req.tool_id == "gobuster":
        if urlsplit(target_url).query:
            raise HTTPException(400, "Remove the query string before running directory enumeration.")
        if not req.wordlist_id:
            raise HTTPException(400, "Select an available backend wordlist before running Gobuster.")
        wordlist_path = str(_resolve_wordlist(req.wordlist_id))
        gobuster_extensions = _normalise_gobuster_extensions(req.extensions)
    gobuster_wildcard_profile = (
        _probe_gobuster_wildcard_length(crawl_target)
        if req.tool_id == "gobuster"
        else None
    )
    gobuster_exclude_length = (
        gobuster_wildcard_profile["exclude_length"]
        if gobuster_wildcard_profile
        else None
    )
    command = _build_tool_command(
        req.tool_id,
        executable,
        crawl_target,
        wordlist_path,
        gobuster_extensions,
        gobuster_exclude_length,
    )
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
    records = _parse_tool_output(req.tool_id, stdout, target_url)
    gobuster_summary = None
    if req.tool_id == "gobuster" and gobuster_wildcard_profile:
        gobuster_summary = _classify_gobuster_records(records, gobuster_wildcard_profile, crawl_target)
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
        "wildcard_summary": gobuster_summary,
        "redirect_chain": redirect_chain if req.tool_id == "katana" else [],
        "stderr": stderr,
        "assessment": (
            "Gobuster ran directory/file enumeration only against the exact approved origin. Random-path baseline responses were used for Gobuster's size exclusion and normalized body fingerprints. Near-size candidates are safely re-fetched on the approved origin without following redirects and compared against baseline body signatures. Similar responses are flagged as suspected wildcard results; distinct responses still require analyst review. Discoveries never expand approved scope."
            if req.tool_id == "gobuster"
            else (
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
            )
        ),
    }
