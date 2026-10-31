"""
Client for the NVD CVE REST API 2.0, used to enrich Metasploit vulnerability
records with authoritative CVSS scores, descriptions, and references.

NVD enforces public rate limits (5 requests/30s without an API key, 50/30s
with one - https://nvd.nist.gov/developers/start-here#divRateLimits). This
client self-throttles to stay under those limits and caches lookups
in-memory for NVD_CACHE_TTL_SECONDS (default 24h) so repeated report
generation or UI refreshes don't re-hit the API for the same CVE. The cache
is not persisted across backend restarts.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from typing import Any

import requests

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Sentinel distinguishing "confirmed no NVD record" from "not yet looked up"
# in the cache, since both would otherwise be indistinguishable from None.
_MISS = object()


def extract_cve_ids(value: Any) -> set[str]:
    """
    Extract CVE IDs from Metasploit reference records and arbitrary nested data.

    Metasploit commonly represents module references as ["CVE", "2021-41773"],
    while database vulnerability references may use {"ctx_id": "CVE",
    "ctx_val": "2021-41773"}. Those split forms do not contain the literal
    "CVE-YYYY-NNNN" token, so handle their CVE context explicitly as well as
    scanning free-form strings for complete identifiers.
    """
    found: set[str] = set()

    def add(raw: Any, *, cve_context: bool = False) -> None:
        if raw is None:
            return
        text = str(raw).strip()
        matches = CVE_ID_RE.findall(text)
        found.update(match.upper() for match in matches)
        if cve_context and re.fullmatch(r"\d{4}-\d{4,7}", text):
            found.add(f"CVE-{text}".upper())

    def visit(item: Any) -> None:
        if isinstance(item, dict):
            context = str(item.get("ctx_id") or item.get("type") or "").strip().upper()
            value = item.get("ctx_val", item.get("value"))
            if context == "CVE":
                add(value, cve_context=True)
            for key, nested in item.items():
                if key not in {"ctx_val", "value"}:
                    visit(nested)
        elif isinstance(item, (list, tuple)):
            if len(item) >= 2 and str(item[0]).strip().upper() == "CVE":
                add(item[1], cve_context=True)
                for nested in item[2:]:
                    visit(nested)
            else:
                for nested in item:
                    visit(nested)
        elif isinstance(item, str):
            add(item)

    visit(value)
    return found


class NvdError(Exception):
    pass


class _TtlCache:
    """Minimal thread-safe in-memory TTL cache."""

    def __init__(self, ttl_seconds: int):
        self.ttl_seconds = max(ttl_seconds, 0)
        self._store: dict[str, tuple[float, Any]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Any:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            expires_at, value = entry
            if time.time() >= expires_at:
                del self._store[key]
                return None
            return value

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._store[key] = (time.time() + self.ttl_seconds, value)


def _summarize(cve: dict[str, Any]) -> dict[str, Any]:
    """Reduce a full NVD CVE record to the fields the UI/report actually use."""
    descriptions = cve.get("descriptions") or []
    description = next(
        (
            entry.get("value")
            for entry in descriptions
            if isinstance(entry, dict) and entry.get("lang") == "en"
        ),
        None,
    )

    metrics = cve.get("metrics") or {}
    cvss = None
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(metric_key)
        if not entries:
            continue
        primary = entries[0] if isinstance(entries, list) else None
        if not isinstance(primary, dict):
            continue
        cvss_data = primary.get("cvssData") or {}
        cvss = {
            "version": cvss_data.get("version"),
            "vector": cvss_data.get("vectorString"),
            "base_score": cvss_data.get("baseScore"),
            "base_severity": cvss_data.get("baseSeverity") or primary.get("baseSeverity"),
            "source_metric": metric_key,
        }
        break

    references = [
        ref.get("url")
        for ref in (cve.get("references") or [])
        if isinstance(ref, dict) and ref.get("url")
    ][:10]

    return {
        "cve_id": cve.get("id"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
        "description": description,
        "cvss": cvss,
        "references": references,
    }


class NvdClient:
    """Thin, self-throttling, caching client for the NVD CVE REST API 2.0."""

    def __init__(self):
        self.api_key = os.getenv("NVD_API_KEY", "").strip() or None
        cache_ttl = int(os.getenv("NVD_CACHE_TTL_SECONDS", "86400"))
        self._cache = _TtlCache(cache_ttl)
        self._throttle_lock = threading.Lock()
        # Stay comfortably under NVD's published limits (5/30s public,
        # 50/30s with a key) even under concurrent requests from the UI.
        self._min_interval_seconds = 0.7 if self.api_key else 6.5
        self._last_request_at = 0.0

    def _throttle(self) -> None:
        with self._throttle_lock:
            now = time.monotonic()
            wait = self._min_interval_seconds - (now - self._last_request_at)
            if wait > 0:
                time.sleep(wait)
            self._last_request_at = time.monotonic()

    def get_cve(self, cve_id: str) -> dict[str, Any] | None:
        """Return a summarized CVE record, or None if NVD has no record for it."""
        normalized = cve_id.strip().upper()
        if not CVE_ID_RE.fullmatch(normalized):
            raise NvdError(f"'{cve_id}' is not a valid CVE identifier.")

        cached = self._cache.get(normalized)
        if cached is _MISS:
            return None
        if cached is not None:
            return cached

        self._throttle()
        headers = {"apiKey": self.api_key} if self.api_key else {}
        try:
            response = requests.get(
                NVD_BASE_URL,
                params={"cveId": normalized},
                headers=headers,
                timeout=20,
            )
        except requests.exceptions.RequestException as exc:
            raise NvdError(f"Could not reach the NVD API: {exc}") from exc

        if response.status_code in (403, 429):
            raise NvdError(
                "NVD rejected the request (rate limited or access denied). "
                "Set NVD_API_KEY in backend/.env for a higher rate limit, then retry."
            )
        if response.status_code != 200:
            raise NvdError(f"NVD HTTP {response.status_code}: {response.text[:300]}")

        try:
            payload = response.json()
        except ValueError as exc:
            raise NvdError("NVD returned a response that could not be parsed as JSON.") from exc

        vulnerabilities = payload.get("vulnerabilities") or []
        if not vulnerabilities:
            self._cache.set(normalized, _MISS)
            return None

        first = vulnerabilities[0]
        cve_record = first.get("cve") if isinstance(first, dict) else None
        if not isinstance(cve_record, dict):
            self._cache.set(normalized, _MISS)
            return None

        summary = _summarize(cve_record)
        self._cache.set(normalized, summary)
        return summary

    def search_cve_ids_by_keyword(self, keyword: str, version: str | None = None) -> set[str]:
        """
        Return the set of CVE IDs the NVD's own keywordSearch finds for a
        confirmed product (optionally narrowed by version, e.g. "vsftpd
        2.3.4"). This is NVD's independent text/CPE match over its own CVE
        corpus - it does not consult Metasploit at all - so a candidate
        module whose own CVE references overlap with this set is a real
        CVE-to-module match, not a name/description guess.

        Results are cached (including an empty result, via the shared
        _MISS sentinel) under a "kw::" prefixed key so they never collide
        with single-CVE cache entries from get_cve().
        """
        keyword = (keyword or "").strip()
        if not keyword:
            return set()
        query = f"{keyword} {version}".strip() if version and version.lower() != "unknown" else keyword
        cache_key = f"kw::{query.lower()}"

        cached = self._cache.get(cache_key)
        if cached is _MISS:
            return set()
        if cached is not None:
            return cached

        self._throttle()
        headers = {"apiKey": self.api_key} if self.api_key else {}
        try:
            response = requests.get(
                NVD_BASE_URL,
                params={"keywordSearch": query, "resultsPerPage": 60},
                headers=headers,
                timeout=20,
            )
        except requests.exceptions.RequestException as exc:
            raise NvdError(f"Could not reach the NVD API: {exc}") from exc

        if response.status_code in (403, 429):
            raise NvdError(
                "NVD rejected the request (rate limited or access denied). "
                "Set NVD_API_KEY in backend/.env for a higher rate limit, then retry."
            )
        if response.status_code != 200:
            raise NvdError(f"NVD HTTP {response.status_code}: {response.text[:300]}")

        try:
            payload = response.json()
        except ValueError as exc:
            raise NvdError("NVD returned a response that could not be parsed as JSON.") from exc

        vulnerabilities = payload.get("vulnerabilities") or []
        cve_ids: set[str] = set()
        for entry in vulnerabilities:
            cve_record = entry.get("cve") if isinstance(entry, dict) else None
            if not isinstance(cve_record, dict) or not cve_record.get("id"):
                continue
            cve_id = str(cve_record["id"]).upper()
            cve_ids.add(cve_id)
            # We already have the full record for each hit - warm the
            # per-CVE cache too, so a later single lookup (e.g. the Verify
            # panel or a report) doesn't re-hit the API for it.
            self._cache.set(cve_id, _summarize(cve_record))

        self._cache.set(cache_key, cve_ids if cve_ids else _MISS)
        return cve_ids


# Shared singleton, mirroring the `rpc` singleton pattern in msf_rpc.py
nvd_client = NvdClient()
