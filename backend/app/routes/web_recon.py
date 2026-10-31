import re
import shutil
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
            return {"target":target_url,"status_code":response.status_code,"reason":response.reason,"final_url":response.url,"redirect_location":headers.get("location"),"title":title,"headers":headers,"technologies":_technology_hints(headers,body),"content_type":response.headers.get("Content-Type"),"body_truncated":total >= 65536,"bytes_inspected":total,"assessment":"HTTP response observed; this probe does not establish whether the application is vulnerable."}
    except requests.exceptions.SSLError as exc:
        raise HTTPException(502, f"TLS negotiation failed: {exc}") from exc
    except requests.exceptions.Timeout as exc:
        raise HTTPException(504, "The web service did not respond within 8 seconds.") from exc
    except requests.exceptions.RequestException as exc:
        raise HTTPException(502, f"HTTP probe failed: {exc}") from exc
    finally:
        session.close()
