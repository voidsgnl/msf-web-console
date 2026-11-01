import hashlib
from html.parser import HTMLParser
import html
import os
import re
import uuid
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, unquote, urljoin, urlsplit, urlunsplit

import requests
from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/web-recon", tags=["web-recon"])

_JOB_EVENTS: dict[str, threading.Event] = {}
_JOB_EVENTS_LOCK = threading.Lock()


def request_job_cancellation(job_id: str) -> bool:
    with _JOB_EVENTS_LOCK:
        event = _JOB_EVENTS.get(job_id)
        if event is None:
            return False
        event.set()
        return True


def _register_job_event(job_id: str) -> threading.Event:
    event = threading.Event()
    with _JOB_EVENTS_LOCK:
        _JOB_EVENTS[job_id] = event
    return event


def _remove_job_event(job_id: str) -> None:
    with _JOB_EVENTS_LOCK:
        _JOB_EVENTS.pop(job_id, None)


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


class ManualPathCheckRequest(BaseModel):
    assessment_id: int = Field(ge=1)
    url: str = Field(min_length=1, max_length=2048)
    paths: list[str] = Field(min_length=1, max_length=25)
    authorized: bool = False


def _normalise_manual_path(raw_path: str) -> str:
    value = raw_path.strip()
    if not value or len(value) > 500 or any(ord(char) < 32 for char in value):
        raise HTTPException(400, "Each manual path must contain 1-500 printable characters.")
    if "\\" in value or "?" in value or "#" in value:
        raise HTTPException(400, "Enter paths only; query strings, fragments, and backslashes are not allowed.")
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or value.startswith("//"):
        raise HTTPException(400, "Manual entries must be relative paths on the approved origin.")
    decoded_segments = unquote(value).split("/")
    if any(segment in {".", ".."} for segment in decoded_segments):
        raise HTTPException(400, "Relative traversal segments are not allowed.")
    return value.lstrip("/")


class _ResponseFeatureParser(HTMLParser):
    """Extract bounded form structure without retaining submitted values or query strings."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.features = {
            "form_count": 0, "input_count": 0, "password_input_count": 0,
            "email_input_count": 0, "link_count": 0, "script_count": 0,
            "button_count": 0, "forms": [],
        }
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        attributes = {key.lower(): value or "" for key, value in attrs}
        if tag == "form":
            self.features["form_count"] += 1
            if len(self.features["forms"]) < 10:
                method = attributes.get("method", "get").strip().upper()
                action = attributes.get("action", "").strip()
                safe_action = "(current page)"
                if action:
                    parsed = urlsplit(action)
                    if parsed.scheme or parsed.netloc:
                        safe_action = "external destination"
                    elif parsed.path:
                        safe_action = parsed.path[:160]
                self._current_form = {
                    "method": method[:10] if method else "GET",
                    "action": safe_action,
                    "inputs": [],
                }
                self.features["forms"].append(self._current_form)
            else:
                self._current_form = None
        elif tag == "input":
            self.features["input_count"] += 1
            input_type = attributes.get("type", "text").lower()
            if input_type == "password":
                self.features["password_input_count"] += 1
            elif input_type == "email":
                self.features["email_input_count"] += 1
            if self._current_form is not None and len(self._current_form["inputs"]) < 25:
                field = {
                    "type": input_type[:24],
                    "name": attributes.get("name", "")[:64] or None,
                    "autocomplete": attributes.get("autocomplete", "")[:40] or None,
                    "required": "required" in attributes,
                }
                self._current_form["inputs"].append(field)
        elif tag == "a" and attributes.get("href"):
            self.features["link_count"] += 1
        elif tag == "script":
            self.features["script_count"] += 1
        elif tag == "button":
            self.features["button_count"] += 1

    def handle_endtag(self, tag):
        if tag == "form":
            self._current_form = None


def _extract_html_response_features(body: bytes, encoding: str | None = None) -> dict:
    """Return HTML structure and safe form metadata, never submitted values or query strings."""
    parser = _ResponseFeatureParser()
    text = body.decode(encoding if isinstance(encoding, str) else "utf-8", errors="replace")
    try:
        parser.feed(text)
        parser.close()
    except Exception:
        pass
    return parser.features



def _fingerprint_html_page(title: str | None, preview: str, features: dict) -> dict:
    """Heuristically label a page from visible text and bounded HTML structure."""
    title_text = (title or "").lower()
    text = (preview or "").lower()
    combined = f"{title_text} {text}"
    forms = features.get("forms", [])
    inputs = [field for form in forms for field in form.get("inputs", [])]
    input_names = " ".join((field.get("name") or "").lower() for field in inputs)
    password_count = features.get("password_input_count", 0)
    email_count = features.get("email_input_count", 0)
    input_count = features.get("input_count", 0)
    script_count = features.get("script_count", 0)
    evidence = []

    if password_count and (
        any(term in combined for term in ("register", "sign up", "signup", "create account", "create your account"))
        or (email_count and input_count >= 4)
        or any(term in input_names for term in ("confirm_password", "password_confirmation"))
    ):
        evidence.append("Password and account-creation form indicators")
        if email_count:
            evidence.append("Email input present")
        return {"page_type": "registration", "confidence": "high" if len(evidence) > 1 else "medium", "evidence": evidence[:4]}

    if password_count and (
        any(term in combined for term in ("log in", "login", "sign in", "signin", "forgot password"))
        or input_count <= 3
    ):
        evidence.append("Password input present")
        if email_count:
            evidence.append("Email input present")
        if any(term in combined for term in ("log in", "login", "sign in", "signin")):
            evidence.append("Login or sign-in wording")
        return {"page_type": "login", "confidence": "high" if len(evidence) >= 2 else "medium", "evidence": evidence[:4]}

    if any(term in combined for term in ("dashboard", "overview", "recent activity", "welcome back")):
        evidence.append("Dashboard or account-overview wording")
        return {"page_type": "dashboard_or_account", "confidence": "medium", "evidence": evidence}

    if any(term in combined for term in ("page not found", "profile not found", "doesn't exist", "does not exist", "we couldn't find", "not found")):
        evidence.append("Not-found or missing-resource wording")
        return {"page_type": "error_or_not_found", "confidence": "high", "evidence": evidence}

    if script_count >= 5 and input_count == 0 and features.get("form_count", 0) == 0:
        evidence.append("Script-heavy page with no server-rendered form controls")
        if len((preview or "").strip()) < 250:
            evidence.append("Very little visible text in the inspected HTML")
        return {"page_type": "possible_spa_shell", "confidence": "medium", "evidence": evidence}

    if features.get("form_count", 0) > 0:
        evidence.append("HTML form present, but no reliable login or registration indicators")
        return {"page_type": "generic_form_page", "confidence": "low", "evidence": evidence}

    if title:
        evidence.append("HTML title present without a stronger page signature")
    return {"page_type": "unclassified", "confidence": "low", "evidence": evidence or ["Insufficient page structure or text for a useful classification"]}

def _check_manual_path(url: str) -> dict:
    session = requests.Session()
    session.trust_env = False
    try:
        with session.get(
            url,
            headers={"User-Agent": "MSF-Web-Console-Recon/0.1", "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"},
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
                if len(body) >= 65536:
                    del body[65536:]
                    break
            raw_body = bytes(body)
            text = raw_body.decode(response.encoding or "utf-8", errors="replace")
            body_signature = _gobuster_body_signature(raw_body, response.encoding)
            body_signature["content_type"] = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            title_match = re.search(r"<title[^>]*>(.*?)</title\s*>", text, re.IGNORECASE | re.DOTALL)
            title = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", title_match.group(1))).strip()[:200] if title_match else None
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() or None
            preview = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", text))).strip()[:800]
            response_features = _extract_html_response_features(raw_body, response.encoding)
            page_fingerprint = _fingerprint_html_page(title, preview, response_features)
            location = response.headers.get("Location")
            return {
                "url": url,
                "status_code": response.status_code,
                "reason": response.reason,
                "response_title": title,
                "response_content_type": content_type,
                "response_preview": preview,
                "response_features": response_features,
                "page_fingerprint": page_fingerprint,
                "content_length": int(response.headers["Content-Length"]) if str(response.headers.get("Content-Length", "")).isdigit() else len(body),
                "bytes_inspected": len(body),
                "body_truncated": len(body) >= 65536,
                "redirect_location": location[:1000] if location else None,
                "_body_signature": body_signature,
                "classification_reason": "HTTP response observed. A status code or page title alone does not prove that the requested resource is a functional endpoint.",
            }
    except requests.exceptions.Timeout:
        return {"url": url, "fetch_state": "unverified", "classification_reason": "Request timed out after 5 seconds."}
    except requests.exceptions.SSLError:
        return {"url": url, "fetch_state": "unverified", "classification_reason": "TLS negotiation failed."}
    except requests.exceptions.RequestException as exc:
        return {"url": url, "fetch_state": "unverified", "classification_reason": f"Request failed: {str(exc)[:240]}"}
    finally:
        session.close()


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


def _classify_manual_path_records(records: list[dict], baseline_signatures: list[dict]) -> list[dict]:
    """Compare manual responses with random-path baselines without asserting endpoint validity."""
    usable = [item for item in baseline_signatures if item.get("status_code") is not None]
    similarity_threshold = 0.85
    review_similarity_threshold = 0.50
    for record in records:
        signature = record.pop("_body_signature", None)
        if signature:
            record["response_fingerprint"] = signature.get("fingerprint")
            record["soft_404_markers"] = signature.get("soft_404_markers", [])
        if not signature or not usable or record.get("status_code") is None:
            continue
        comparable = [item for item in usable if item.get("status_code") == record.get("status_code")
                      and item.get("content_type") == signature.get("content_type")]
        similarities = [_gobuster_body_similarity(signature, item) for item in comparable]
        best = max(similarities, default=0.0)
        candidate_markers = set(signature.get("soft_404_markers", []))
        # Only trust a not-found phrase as corroborating evidence if it appears
        # in more than one baseline sample. A phrase seen in just a single
        # random-path fetch can be coincidental (e.g. generic copy that also
        # happens to appear on a real page), and should not by itself be
        # enough to override a low overall body-similarity score.
        marker_counts: dict[str, int] = {}
        for item in comparable:
            for marker in item.get("soft_404_markers", []):
                marker_counts[marker] = marker_counts.get(marker, 0) + 1
        stable_baseline_markers = (
            {marker for marker, count in marker_counts.items() if count >= 2}
            if len(comparable) >= 2
            else set()
        )
        shared = sorted(candidate_markers & stable_baseline_markers)
        record["body_similarity"] = round(best, 4) if comparable else None
        record["baseline_samples_compared"] = len(comparable)
        # Keep marker evidence independent from body similarity so analysts
        # can see exactly which signals contributed to the classification.
        record["shared_not_found_markers"] = shared
        record["shared_not_found_marker_count"] = len(shared)
        high_similarity = bool(comparable and best >= similarity_threshold)
        corroborated_markers = bool(
            comparable
            and len(shared) >= 2
            and best >= review_similarity_threshold
        )
        # Similarity >= 85% remains sufficient. Marker-based classification
        # requires at least two distinct markers, stable across baseline
        # samples, plus at least 50% body similarity.
        if comparable and (high_similarity or corroborated_markers):
            record["response_classification"] = "likely_soft_404"
            detail = f"body similarity {best:.0%}"
            marker_detail = (
                f"; {len(shared)} shared not-found markers: {', '.join(shared)}"
                if shared else "; no shared not-found markers"
            )
            record["classification_reason"] = (
                f"Random-path comparison: {detail}{marker_detail}. "
                "Treat as a likely soft 404, not a confirmed endpoint."
            )
        elif comparable and shared:
            record["response_classification"] = "needs_verification"
            record["classification_reason"] = (
                f"Random-path comparison: body similarity {best:.0%}; "
                f"{len(shared)} shared not-found marker(s): {', '.join(shared)}. "
                "Marker evidence did not meet the two-marker and 50% similarity "
                "requirements; verify the page manually."
            )
        elif comparable:
            record["response_classification"] = "distinct_response"
            record["classification_reason"] = (
                f"Random-path comparison: body similarity {best:.0%}; "
                "no shared not-found markers. This is not proof of a functional endpoint."
            )
    return records


def _collect_manual_path_baseline(origin: str) -> dict:
    """Collect random-path responses and retain failures for transparent diagnostics."""
    signatures = []
    failures = []
    attempted = 3
    for _ in range(attempted):
        probe_url = urljoin(origin, str(uuid.uuid4()))
        record = _check_manual_path(probe_url)
        signature = record.pop("_body_signature", None)
        if signature and record.get("status_code") is not None:
            signatures.append({
                "status_code": record["status_code"],
                "content_type": signature.get("content_type"),
                "fingerprint": signature.get("fingerprint"),
                "shingles": signature.get("shingles", set()),
                "soft_404_markers": signature.get("soft_404_markers", []),
            })
        else:
            failures.append({
                "fetch_state": record.get("fetch_state", "unverified"),
                "reason": record.get("classification_reason", "No usable HTTP response was returned."),
            })
    successful = len(signatures)
    return {
        "status": "available" if successful == attempted else "partial" if successful else "unavailable",
        "attempted": attempted,
        "successful": successful,
        "failed": attempted - successful,
        "failures": failures,
        "signatures": signatures,
    }

@router.post("/directories/check")
def check_manual_directories(req: ManualPathCheckRequest):
    """Check a bounded list of analyst-supplied relative paths on one approved origin."""
    if not req.authorized:
        raise HTTPException(400, "Confirm that you own this target or have explicit permission to assess it.")
    target_url = _normalise_url(req.url)
    from app.routes.assessments import assert_target_in_scope, record_tool_execution
    scope = assert_target_in_scope(req.assessment_id, target_url)
    target = urlsplit(target_url)
    origin = urlunsplit((target.scheme, target.netloc, "/", "", ""))
    paths = list(dict.fromkeys(_normalise_manual_path(item) for item in req.paths))
    if not paths:
        raise HTTPException(400, "Enter at least one relative path.")
    urls = [urljoin(origin, path) for path in paths]
    if any(urlsplit(url).netloc.lower() != target.netloc.lower() or urlsplit(url).scheme.lower() != target.scheme.lower() for url in urls):
        raise HTTPException(400, "Manual paths must remain on the exact approved origin.")
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    baseline = _collect_manual_path_baseline(origin)
    baseline_signatures = baseline["signatures"]
    with ThreadPoolExecutor(max_workers=2) as executor:
        records = list(executor.map(_check_manual_path, urls))
    records = _classify_manual_path_records(records, baseline_signatures)
    for record in records:
        record["baseline_sample_count"] = baseline["successful"]
        if not baseline_signatures:
            record["response_classification"] = "baseline_unavailable"
            record["body_similarity"] = None
            record["baseline_samples_compared"] = 0
            path_reason = record.get("classification_reason")
            baseline_reason = "; ".join(sorted({item["reason"] for item in baseline["failures"]}))
            record["classification_reason"] = (
                (f"Path request: {path_reason} " if path_reason else "")
                + f"Random-path baseline unavailable: {baseline_reason} "
                + "Response comparison was skipped; this result is unclassified."
            )
    finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    execution = record_tool_execution(
        scope, "manual-path-check", origin, started_at, finished_at,
        0 if all(record.get("status_code") is not None for record in records) else 1,
        any(record.get("body_truncated") for record in records),
        records, "",
    )
    return {
        "execution_id": execution["id"],
        "assessment_id": req.assessment_id,
        "cancelled": bool(completed.get("cancelled")),
        "tool_id": "manual-path-check",
        "target": origin,
        "records": records,
        "baseline": {
            "status": baseline["status"], "attempted": baseline["attempted"],
            "successful": baseline["successful"], "failed": baseline["failed"],
            "failures": baseline["failures"],
            "comparison": "same status and content type; normalized body shingles and common not-found markers",
        },
        "assessment": f"Checked {len(records)} manually supplied paths against {len(baseline_signatures)} random-path baseline sample(s). At most two requests ran concurrently; redirects were not followed. Classifications are response comparisons, not endpoint or vulnerability confirmation.",
    }


@router.get("/tools")
def list_tools():
    """Report local tool availability; never executes the tools."""
    tools = []
    for item in TOOL_CATALOG:
        path = shutil.which(item["id"])
        execution_enabled = item["id"] in RUNNABLE_TOOLS
        tools.append({
            **item,
            "installed": path is not None,
            "path": path,
            "execution_enabled": execution_enabled,
            "status": (
                "ready" if execution_enabled and path
                else "not_installed" if execution_enabled
                else "not_integrated"
            ),
        })
    return {
        "tools": tools,
        "built_in": [{
            "name": "HTTP response probe",
            "available": True,
            "description": "One bounded HTTP GET; no crawling or vulnerability testing.",
        }],
    }


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
    "ffuf": {"name": "FFUF (directory enumeration)", "timeout": 180, "max_output": 1048576},
    "feroxbuster": {"name": "Feroxbuster (directory enumeration)", "timeout": 180, "max_output": 1048576},
    "nuclei": {"name": "Nuclei (HTTP vulnerability templates)", "timeout": 300, "max_output": 1048576},
    "nikto": {"name": "Nikto (web server checks)", "timeout": 150, "max_output": 1048576},
    "wpscan": {"name": "WPScan (passive WordPress assessment)", "timeout": 180, "max_output": 1048576},
    "amass": {"name": "Amass (passive asset discovery)", "timeout": 150, "max_output": 1048576},
    "testssl.sh": {"name": "testssl.sh (TLS analysis)", "timeout": 240, "max_output": 1048576},
    "nmap": {"name": "Nmap (bounded TCP service discovery)", "timeout": 120, "max_output": 1048576},
}


class ToolRunRequest(BaseModel):
    assessment_id: int = Field(ge=1)
    tool_id: str = Field(pattern=r"^(httpx|whatweb|subfinder|katana|gobuster|ffuf|feroxbuster|nuclei|nikto|wpscan|amass|testssl[.]sh|nmap)$")
    url: str = Field(min_length=1, max_length=2048)
    authorized: bool = False
    wordlist_id: str | None = Field(default=None, max_length=512)
    extensions: str = Field(default="", max_length=120)



def _project_wordlist_root() -> Path:
    """Return the repository-local directory for untracked wordlist datasets."""
    return Path(__file__).resolve().parents[3] / "wordlists"


def _wordlist_roots() -> list[Path]:
    configured = os.environ.get("MSF_WEB_WORDLIST_DIRS")
    # An explicit configuration is authoritative. This keeps deployments and
    # tests isolated from unrelated wordlists installed elsewhere on the host.
    # When unset, use the project-local and standard system locations.
    values = configured.split(os.pathsep) if configured is not None else [
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
    if tool_id == "ffuf":
        if not wordlist_path:
            raise HTTPException(400, "Select an available backend wordlist before running FFUF.")
        return [
            executable, "-u", target_url.rstrip("/") + "/FUZZ", "-w", wordlist_path,
            "-json", "-noninteractive", "-s", "-c",
            "-t", "1", "-rate", "2", "-timeout", "8",
            "-mc", "200,204,301,302,307,401,403",
        ]
    if tool_id == "feroxbuster":
        if not wordlist_path:
            raise HTTPException(400, "Select an available backend wordlist before running Feroxbuster.")
        return [
            executable, "--url", target_url.rstrip("/") + "/",
            "--wordlist", wordlist_path, "--json", "--silent",
            "--no-recursion", "--threads", "1", "--rate-limit", "2",
            "--timeout", "8", "--status-codes", "200,204,301,302,307,401,403",
            "--output", "/dev/stdout",
        ]
    if tool_id == "nuclei":
        return [
            executable, "-u", target_url,
            "-jsonl", "-silent", "-nc", "-ni", "-dr", "-dut",
            "-pt", "http", "-ept", "dns,file,headless,tcp,workflow,ssl,websocket,whois,code,javascript",
            "-s", "info,low,medium,high,critical",
            "-rl", "2", "-c", "1", "-bs", "1", "-timeout", "8", "-retries", "0",
            "-ot",
        ]
    if tool_id == "nikto":
        return [
            executable, "-host", target_url, "-Format", "json", "-output", "/dev/stdout",
            "-maxtime", "90s", "-nointeractive", "-nocheck",
        ]
    if tool_id == "wpscan":
        return [
            executable, "--url", target_url, "--format", "json", "--output", "/dev/stdout",
            "--detection-mode", "passive", "--plugins-detection", "passive",
            "--max-threads", "1", "--throttle", "500",
            "--request-timeout", "8", "--connect-timeout", "5",
        ]
    if tool_id == "amass":
        hostname = (urlsplit(target_url).hostname or "").lower()
        if not hostname:
            raise HTTPException(400, "A valid approved hostname is required for passive Amass discovery.")
        return [executable, "enum", "-passive", "-d", hostname, "-json", "/dev/stdout", "-timeout", "2"]
    if tool_id == "testssl.sh":
        parsed = urlsplit(target_url)
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            raise HTTPException(400, "testssl.sh requires an HTTPS target in the approved assessment scope.")
        host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
        port = parsed.port or 443
        return [
            executable, "--fast", "--quiet", "--warnings", "off",
            "--connect-timeout", "5", "--openssl-timeout", "8",
            "--jsonfile", "/dev/stdout", f"{host}:{port}",
        ]
    if tool_id == "nmap":
        hostname = (urlsplit(target_url).hostname or "").lower()
        if not hostname:
            raise HTTPException(400, "A valid approved hostname or IP is required for Nmap.")
        command = [
            executable, "-n", "-Pn", "-sT", "-sV", "--version-light",
            "--top-ports", "100", "--max-retries", "1", "--host-timeout", "90s",
            "--reason", "-oX", "-", hostname,
        ]
        if ":" in hostname:
            command.insert(1, "-6")
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
        r"""(?is)(<input\b[^>]*(?:name|id)=["'](?:csrf|csrf_token|nonce|authenticity_token|requestverificationtoken)["'][^>]*value=["'])[^"']+(["'])""",
        r"\1<dynamic-token>\2",
        text,
    )
    text = re.sub(
        r"(?i)(csrf(?:token)?|nonce|authenticity_token|requestverificationtoken)([\s:=\"']+)[a-z0-9._~-]{8,}",
        r"\1\2<dynamic-token>",
        text,
    )
    decoded_text = html.unescape(text)
    title_match = re.search(r"(?is)<title[^>]*>(.*?)</title>", decoded_text)
    title = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", title_match.group(1))).strip().lower() if title_match else ""
    searchable = re.sub(r"<[^>]+>", " ", decoded_text).lower()
    soft_404_phrases = (
        "profile not found",
        "this profile doesn't exist",
        "this profile does not exist",
        "this profile has been removed",
        "page not found",
        "404 not found",
        "the requested url was not found",
        "the requested resource was not found",
        "the requested page could not be found",
        "we couldn't find the page",
        "we could not find the page",
    )
    soft_404_markers = sorted(phrase for phrase in soft_404_phrases if phrase in searchable)
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
        "title": title,
        "soft_404_markers": soft_404_markers,
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
            signature = _gobuster_body_signature(bytes(body), response.encoding)
            signature["content_type"] = response.headers.get("Content-Type", "").split(";")[0].strip().lower()
            return response.status_code, signature
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
                        "content_type": response.headers.get("Content-Type", "").split(";")[0].strip().lower(),
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


def _parse_content_discovery_json(tool_id: str, output: str, target_url: str) -> list[dict]:
    import json

    approved_origin = _origin_key(target_url)
    records: list[dict] = []
    for line in output.splitlines():
        value = line.strip()
        if not value:
            continue
        try:
            item = json.loads(value)
        except (TypeError, ValueError):
            continue
        if not isinstance(item, dict):
            continue
        if tool_id == "ffuf":
            if not isinstance(item.get("url"), str) or not isinstance(item.get("status"), int):
                continue
            endpoint = item["url"]
            status = item["status"]
            content_length = item.get("length")
            method = "GET"
            source = "ffuf"
        else:
            if item.get("type") != "response" or not isinstance(item.get("url"), str):
                continue
            endpoint = item["url"]
            status = item.get("status")
            content_length = item.get("content_length")
            method = str(item.get("method") or "GET")[:12]
            source = "feroxbuster"
        try:
            parsed = urlsplit(endpoint)
            if (
                _origin_key(endpoint) != approved_origin
                or parsed.username or parsed.password or parsed.fragment
                or parsed.scheme.lower() not in {"http", "https"}
            ):
                continue
        except (TypeError, ValueError):
            continue
        records.append({
            "url": endpoint,
            "path": parsed.path or "/",
            "status_code": status if isinstance(status, int) else None,
            "content_length": content_length if isinstance(content_length, int) else None,
            "method": method,
            "discovery_type": "directory" if (parsed.path or "").endswith("/") else "path",
            "source": source,
        })
    deduplicated: dict[tuple[str, str], dict] = {}
    for record in records:
        key = (record["method"], record["url"])
        if key in deduplicated:
            deduplicated[key]["observations"] += 1
        else:
            record["observations"] = 1
            deduplicated[key] = record
    return list(deduplicated.values())


def _parse_nuclei_output(output: str, target_url: str) -> list[dict]:
    import json

    approved_origin = _origin_key(target_url)
    records: list[dict] = []
    for line in output.splitlines():
        value = line.strip()
        if not value:
            continue
        try:
            item = json.loads(value)
        except (TypeError, ValueError):
            continue
        if not isinstance(item, dict):
            continue
        matched_at = item.get("matched-at") or item.get("host")
        if not isinstance(matched_at, str):
            continue
        try:
            parsed = urlsplit(matched_at)
            if (
                parsed.scheme.lower() not in {"http", "https"}
                or parsed.username or parsed.password or parsed.fragment
                or _origin_key(matched_at) != approved_origin
            ):
                continue
        except (TypeError, ValueError):
            continue
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        severity = str(info.get("severity") or item.get("severity") or "unknown").lower()[:20]
        extracted = item.get("extracted-results")
        if isinstance(extracted, list):
            extracted = [str(result)[:500] for result in extracted[:20]]
        else:
            extracted = []
        records.append({
            "url": matched_at,
            "path": parsed.path or "/",
            "status_code": item.get("status_code") if isinstance(item.get("status_code"), int) else None,
            "template_id": str(item.get("template-id") or "")[:160],
            "template_name": str(info.get("name") or "")[:300],
            "severity": severity,
            "matched_at": matched_at,
            "matcher_name": str(item.get("matcher-name") or "")[:160] or None,
            "template_type": str(item.get("type") or "http")[:40],
            "extracted_results": extracted,
            "source": "nuclei",
            "evidence_type": "scanner_match",
            "assessment": "Nuclei template match retained as evidence; it is not a confirmed vulnerability verdict.",
        })
    deduplicated: dict[tuple[str, str, str], dict] = {}
    for record in records:
        key = (record["template_id"], record["url"], record["matcher_name"] or "")
        if key in deduplicated:
            deduplicated[key]["observations"] += 1
        else:
            record["observations"] = 1
            deduplicated[key] = record
    return list(deduplicated.values())


def _classify_gobuster_records(records: list[dict], wildcard_profile: dict, target_url: str) -> dict:
    """Compare near-baseline responses with normalized body fingerprints."""
    baseline_statuses = set(wildcard_profile.get("status_codes", []))
    baseline_signatures = wildcard_profile.get("body_signatures", [])
    reference_length = int(wildcard_profile.get("reference_length", 0))
    tolerance = int(wildcard_profile.get("length_tolerance", 128))
    similarity_threshold = 0.92
    review_similarity_threshold = 0.80
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
    likely_soft_404 = 0
    needs_verification = 0
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
            record["response_title"] = signature.get("title") or None
            record["response_content_type"] = signature.get("content_type") or None
            baseline_marker_counts: dict[str, int] = {}
            for item in comparable:
                for marker in item.get("soft_404_markers", []):
                    baseline_marker_counts[marker] = baseline_marker_counts.get(marker, 0) + 1
            stable_baseline_markers = {
                marker for marker, count in baseline_marker_counts.items() if count >= 2
            }
            shared_soft_404_markers = sorted(
                set(signature.get("soft_404_markers", [])) & stable_baseline_markers
            )
            if shared_soft_404_markers:
                record["response_classification"] = "likely_soft_404"
                record["soft_404_markers"] = shared_soft_404_markers
                group_material = "|".join((
                    str(status),
                    str(record.get("response_title") or "").strip().lower(),
                    str(record.get("response_content_type") or "").split(";", 1)[0].strip().lower(),
                    ",".join(shared_soft_404_markers),
                ))
                record["response_group_id"] = "soft404-" + hashlib.sha256(
                    group_material.encode("utf-8")
                ).hexdigest()[:12]
                record["classification_reason"] = (
                    "Response contains an application-level not-found message also present "
                    "in multiple random-path baselines: "
                    + ", ".join(shared_soft_404_markers)
                    + ". Treat as a likely soft 404, not a confirmed endpoint."
                )
                likely_soft_404 += 1
            elif similarity >= similarity_threshold:
                record["response_classification"] = "suspected_wildcard"
                record["classification_reason"] = (
                    f"Normalized response body matches a random-path baseline "
                    f"({similarity:.1%} similarity; HTTP {status}; {length:,} bytes). "
                    "Review before treating it as a real path."
                )
                suspected += 1
            elif similarity >= review_similarity_threshold:
                record["response_classification"] = "needs_verification"
                record["classification_reason"] = (
                    f"Response is similar to, but not conclusive against, the random-path baseline "
                    f"({similarity:.1%} similarity; review band {review_similarity_threshold:.0%}-{similarity_threshold:.0%}). "
                    "Verify the page content before treating it as a discovered endpoint."
                )
                needs_verification += 1
            else:
                record["response_classification"] = "distinct_response"
                record["classification_reason"] = (
                    f"Response body differs from the random-path baseline "
                    f"({similarity:.1%} similarity). This is a distinct response, not proof that the path is valid."
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
        "review_similarity_threshold": review_similarity_threshold,
        "body_fingerprint_checks": fingerprint_checks,
        "body_fingerprint_check_limit": max_fingerprint_checks,
        "suspected_wildcard": suspected,
        "likely_soft_404": likely_soft_404,
        "needs_verification": needs_verification,
        "distinct_response": distinct,
        "unverified": unverified,
        "total": len(records),
    }

def _parse_specialist_tool_output(tool_id: str, output: str, target_url: str) -> list[dict]:
    """Normalize specialist scanner output into bounded, reviewable evidence."""
    import json
    import xml.etree.ElementTree as ET

    if tool_id == "nmap":
        try:
            root = ET.fromstring(output)
        except ET.ParseError:
            return []
        records = []
        for host_node in root.findall(".//host"):
            address_node = host_node.find("./address")
            host_value = address_node.get("addr") if address_node is not None else (urlsplit(target_url).hostname or "")
            for port_node in host_node.findall("./ports/port"):
                state_node = port_node.find("state")
                if state_node is None or state_node.get("state") != "open":
                    continue
                service_node = port_node.find("service")
                records.append({
                    "host": host_value,
                    "port": int(port_node.get("portid", "0")),
                    "protocol": port_node.get("protocol", "tcp"),
                    "state": "open",
                    "service": service_node.get("name") if service_node is not None else None,
                    "product": service_node.get("product") if service_node is not None else None,
                    "version": service_node.get("version") if service_node is not None else None,
                    "source": "nmap",
                    "evidence_type": "open_service",
                    "assessment": "Open TCP service observed by a bounded top-100-port connect scan; verify exposure and ownership before further testing.",
                })
        return records

    if tool_id == "amass":
        records = []
        approved_host = (urlsplit(target_url).hostname or "").lower().rstrip(".")
        for line in output.splitlines():
            try:
                item = json.loads(line)
            except (TypeError, ValueError):
                continue
            if not isinstance(item, dict):
                continue
            name = item.get("name") or item.get("domain")
            if not isinstance(name, str):
                continue
            name = name.lower().rstrip(".")
            if name != approved_host and not name.endswith("." + approved_host):
                continue
            sources = item.get("sources") if isinstance(item.get("sources"), list) else []
            records.append({
                "host": name, "sources": [str(source)[:100] for source in sources[:20]],
                "source": "amass", "evidence_type": "passive_subdomain",
                "assessment": "Passive Amass discovery only; this hostname is an inventory lead, not an approved target.",
            })
        return records

    try:
        document = json.loads(output)
    except (TypeError, ValueError):
        return [{"raw": line[:4000], "source": tool_id} for line in output.splitlines() if line.strip()][:100]

    if tool_id == "wpscan":
        if not isinstance(document, dict):
            return []
        version = document.get("version") if isinstance(document.get("version"), dict) else {}
        plugins = document.get("plugins") if isinstance(document.get("plugins"), dict) else {}
        themes = document.get("themes") if isinstance(document.get("themes"), dict) else {}
        findings = document.get("interesting_findings") if isinstance(document.get("interesting_findings"), list) else []
        return [{
            "target": target_url, "source": "wpscan",
            "wordpress_version": version.get("number"),
            "plugin_count": len(plugins), "theme_count": len(themes),
            "finding_count": len(findings),
            "raw": json.dumps({
                "version": version.get("number"),
                "plugins": list(plugins.keys())[:50],
                "themes": list(themes.keys())[:25],
                "interesting_findings": findings[:25],
            }, ensure_ascii=False)[:12000],
            "assessment": "WPScan used passive detection modes. Results are evidence and require analyst validation; vulnerability data may be incomplete without a WPScan API token.",
        }]

    if tool_id == "nikto":
        if not isinstance(document, dict):
            return []
        items = document.get("vulnerabilities") or document.get("findings") or document.get("items") or []
        if not isinstance(items, list):
            items = []
        if not items:
            return [{
                "target": target_url, "source": "nikto",
                "raw": json.dumps(document, ensure_ascii=False)[:12000],
                "assessment": "Nikto output retained for review; a scanner message is not a confirmed vulnerability.",
            }]
        return [{
            "target": str(item.get("url") or target_url)[:2048],
            "source": "nikto",
            "finding": str(item.get("msg") or item.get("message") or item.get("description") or item.get("id") or "Nikto observation")[:1000],
            "severity": str(item.get("severity") or "unknown")[:30],
            "raw": json.dumps(item, ensure_ascii=False)[:4000],
            "assessment": "Nikto observation retained as evidence; verify manually before classifying it as a vulnerability.",
        } for item in items[:200] if isinstance(item, dict)]

    if tool_id == "testssl.sh":
        items = document if isinstance(document, list) else [document]
        records = []
        for item in items[:500]:
            if not isinstance(item, dict):
                continue
            records.append({
                "target": target_url, "source": "testssl.sh",
                "finding": str(item.get("finding") or item.get("id") or item.get("severity") or "TLS observation")[:1000],
                "severity": str(item.get("severity") or "unknown")[:30],
                "raw": json.dumps(item, ensure_ascii=False)[:4000],
                "assessment": "TLS configuration observation; interpret in context and verify certificate/protocol findings.",
            })
        return records
    return []


def _parse_tool_output(tool_id: str, output: str, target_url: str | None = None) -> list[dict]:
    import json
    if tool_id == "gobuster":
        return _parse_gobuster_output(output, target_url or "")
    if tool_id in {"ffuf", "feroxbuster"}:
        return _parse_content_discovery_json(tool_id, output, target_url or "")
    if tool_id == "nuclei":
        return _parse_nuclei_output(output, target_url or "")
    if tool_id in {"nikto", "wpscan", "amass", "testssl.sh", "nmap"}:
        return _parse_specialist_tool_output(tool_id, output, target_url or "")

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

def _terminate_process_group(process) -> None:
    """Stop the scanner and any child processes it started."""
    import signal
    import subprocess

    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except OSError:
        try:
            process.terminate()
        except OSError:
            pass

    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass

    # Remove any descendants that may still hold inherited output pipes.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        # The OS has already been asked to kill the process group. Do not block
        # the API worker indefinitely if a broken child refuses to exit.
        pass


def _run_bounded_process(command: list[str], config: dict, env: dict, cancel_event=None) -> dict:
    """Run an adapter with a wall-clock deadline and a combined stdout/stderr cap.

    Pipes are drained continuously so a noisy child cannot deadlock on a full
    pipe. Only max_output bytes are retained in memory; excess output triggers
    process-group termination and is discarded.
    """
    import subprocess
    import threading
    import time

    max_output = int(config["max_output"])
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    captured = {"total": 0}
    lock = threading.Lock()
    output_limit_reached = threading.Event()

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        env=env,
        shell=False,
        start_new_session=True,
        bufsize=0,
    )

    def drain(pipe, destination: bytearray) -> None:
        try:
            while True:
                chunk = pipe.read(8192)
                if not chunk:
                    break
                with lock:
                    available = max_output - captured["total"]
                    if available > 0:
                        kept = chunk[:available]
                        destination.extend(kept)
                        captured["total"] += len(kept)
                    if len(chunk) > max(available, 0):
                        output_limit_reached.set()
        finally:
            pipe.close()

    readers = [
        threading.Thread(target=drain, args=(process.stdout, stdout_buffer), daemon=True),
        threading.Thread(target=drain, args=(process.stderr, stderr_buffer), daemon=True),
    ]
    for reader in readers:
        reader.start()

    deadline = time.monotonic() + float(config["timeout"])
    timed_out = False
    cancelled = False
    while process.poll() is None:
        if cancel_event is not None and cancel_event.is_set():
            cancelled = True
            _terminate_process_group(process)
            break
        if output_limit_reached.is_set():
            _terminate_process_group(process)
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            _terminate_process_group(process)
            break
        time.sleep(min(0.05, remaining))

    for reader in readers:
        reader.join(timeout=0.25)
    if any(reader.is_alive() for reader in readers):
        _terminate_process_group(process)
    for reader in readers:
        reader.join(timeout=2)

    if timed_out:
        raise subprocess.TimeoutExpired(command, config["timeout"])

    with lock:
        stdout = bytes(stdout_buffer).decode("utf-8", errors="replace")
        stderr = bytes(stderr_buffer).decode("utf-8", errors="replace")
        output_size = captured["total"]

    if output_limit_reached.is_set():
        note = "Output limit reached; scanner process group was terminated."
        stderr = (stderr + "\\n" + note).strip()

    return {
        "returncode": process.returncode if process.returncode is not None else 1,
        "stdout": stdout,
        "stderr": stderr[:4000],
        "output_size": output_size,
        "output_truncated": output_limit_reached.is_set(),
        "cancelled": cancelled,
    }


@router.post("/run")
def run_recon_tool(req: ToolRunRequest, cancel_event=None):
    """Run one fixed, bounded reconnaissance adapter against one authorized URL."""
    import os
    import subprocess

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
    if req.tool_id in {"gobuster", "ffuf", "feroxbuster"}:
        if urlsplit(target_url).query:
            raise HTTPException(400, "Remove the query string before running content discovery.")
        if not req.wordlist_id:
            raise HTTPException(400, "Select an available backend wordlist before running content discovery.")
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
        completed = _run_bounded_process(
            command,
            config,
            {
                "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                "HOME": os.path.expanduser("~"),
                "LANG": os.environ.get("LANG", "C.UTF-8"),
                "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
            },
            cancel_event=cancel_event,
        )
        output_size = completed["output_size"]
        stdout = completed["stdout"]
        stderr = completed["stderr"]
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
        completed["returncode"], completed["output_truncated"], records, stderr,
    )
    if req.tool_id == "gobuster":
        assessment_text = (
            "Gobuster ran directory/file enumeration only against the exact approved origin. "
            "Random-path baseline responses were used for Gobuster's size exclusion and normalized "
            "body fingerprints. Up to 100 near-size candidates are safely re-fetched on the approved "
            "origin without following redirects and compared against baseline body signatures; "
            "candidates beyond that cap remain unverified. Similar responses are flagged as suspected "
            "wildcard results; distinct responses still require analyst review. Discoveries never "
            "expand approved scope."
        )
    elif req.tool_id in {"ffuf", "feroxbuster"}:
        assessment_text = (
            f"{config['name']} ran fixed directory/file enumeration only against the exact approved "
            "origin, using a backend-selected wordlist, one worker, a 2 requests/second rate limit, "
            "and redirects disabled. Only same-origin JSON results are retained as evidence; "
            "discoveries never expand approved scope."
        )
    elif req.tool_id == "nuclei":
        assessment_text = (
            "Nuclei ran the backend-owned HTTP template policy against the exact approved target "
            "with redirects, OAST/Interactsh, non-HTTP protocols, and raw template output disabled. "
            "Requests were bounded to one template worker and 2 requests/second with no retries. "
            "Template matches are evidence for analyst review, not confirmed vulnerability verdicts; "
            "they do not expand approved scope."
        )
    elif req.tool_id == "amass":
        assessment_text = (
            "Amass ran passive enumeration only. Discovered hostnames remain out-of-scope inventory leads "
            "and are never automatically approved or actively probed."
        )
    elif req.tool_id == "nmap":
        assessment_text = (
            "Nmap ran a fixed TCP connect scan of the 100 most common ports with light service detection, "
            "one retry, and a 90-second host timeout. No scripts, UDP scan, OS detection, or arbitrary port "
            "ranges were enabled. Open ports are observations, not vulnerability findings."
        )
    elif req.tool_id == "testssl.sh":
        assessment_text = (
            "testssl.sh ran its fast TLS configuration checks against the exact approved HTTPS hostname and port. "
            "TLS observations are evidence for review, not automatic vulnerability verdicts."
        )
    elif req.tool_id == "wpscan":
        assessment_text = (
            "WPScan ran in passive detection mode with one worker and a request throttle. "
            "Vulnerability intelligence may be incomplete without an API token; observations require review."
        )
    elif req.tool_id == "nikto":
        assessment_text = (
            "Nikto ran with a fixed maximum duration and non-interactive output. Its observations are evidence "
            "for analyst review, not confirmed vulnerabilities."
        )
    elif req.tool_id == "subfinder":
        assessment_text = (
            "Subfinder uses passive data sources only. Discovered hostnames are inventory leads, "
            "not approved targets; this adapter does not initiate DNS probes or HTTP requests."
        )
    elif req.tool_id == "katana":
        assessment_text = (
            "Katana used a shallow, time- and page-bounded crawl restricted to the approved "
            "scheme/host/port. The entry URL was preflighted and only same-origin redirects "
            "were followed; crawler-discovered page redirects remain disabled. Cross-origin "
            "redirects are not followed, and discovered URLs do not expand approved scope."
            + (f" Redirect note: {redirect_note.get('reason') or redirect_note.get('error')}" if redirect_note else "")
        )
    else:
        assessment_text = "Tool output is reconnaissance evidence, not a confirmed vulnerability verdict."

    return {
        "execution_id": execution["id"],
        "assessment_id": req.assessment_id,
        "tool_id": req.tool_id,
        "tool": config["name"],
        "target": target_url,
        "exit_code": completed["returncode"],
        "timed_out": False,
        "output_truncated": completed["output_truncated"],
        "records": records,
        "wildcard_summary": gobuster_summary,
        "redirect_chain": redirect_chain if req.tool_id == "katana" else [],
        "stderr": stderr,
        "assessment": assessment_text,
    }

def _run_recon_job_background(job_id: str, req: ToolRunRequest) -> None:
    from app.routes.assessments import update_execution_job

    event = _register_job_event(job_id)
    try:
        if event.is_set():
            update_execution_job(job_id, "cancelled", error="Cancelled before scanner start.")
            return
        update_execution_job(job_id, "running")
        result = run_recon_tool(req, cancel_event=event)
        if result.get("cancelled"):
            update_execution_job(
                job_id, "cancelled", execution_id=result.get("execution_id"),
                error="Cancelled by operator; partial output was retained.",
            )
        else:
            update_execution_job(job_id, "completed", execution_id=result.get("execution_id"))
    except HTTPException as exc:
        update_execution_job(job_id, "failed", error=str(exc.detail))
    except Exception as exc:
        update_execution_job(job_id, "failed", error=f"Unexpected execution error: {str(exc)[:800]}")
    finally:
        _remove_job_event(job_id)


@router.post("/run/async", status_code=202)
def queue_recon_tool(req: ToolRunRequest, background_tasks: BackgroundTasks):
    """Queue a bounded scanner execution and return a persistent job identifier."""
    if not req.authorized:
        raise HTTPException(400, "Confirm that you own this target or have explicit permission to assess it.")
    target_url = _normalise_url(req.url)
    from app.routes.assessments import assert_target_in_scope, create_execution_job
    assert_target_in_scope(req.assessment_id, target_url)
    config = RUNNABLE_TOOLS.get(req.tool_id)
    if not config:
        raise HTTPException(400, "This reconnaissance tool is not enabled for execution.")
    if not shutil.which(req.tool_id):
        raise HTTPException(409, f"{config['name']} is not installed or is not available on the backend PATH.")
    # Validate option-dependent inputs before accepting the job.
    if req.tool_id in {"gobuster", "ffuf", "feroxbuster"}:
        if urlsplit(target_url).query:
            raise HTTPException(400, "Remove the query string before running content discovery.")
        if not req.wordlist_id:
            raise HTTPException(400, "Select an available backend wordlist before running content discovery.")
        _resolve_wordlist(req.wordlist_id)
        _normalise_gobuster_extensions(req.extensions)
    job = create_execution_job(req.assessment_id, req.tool_id, target_url)
    _register_job_event(job["id"])
    background_tasks.add_task(_run_recon_job_background, job["id"], req)
    return job
