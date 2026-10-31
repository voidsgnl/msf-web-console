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


_VERSION_NUMERIC_RE = re.compile(r"\d+(?:\.\d+)*")


def _parse_version_tuple(version: str | None) -> tuple[int, ...] | None:
    """
    Parse a dotted version string into a tuple of integers for ordered
    comparison, e.g. "7.2p2" -> (7, 2), "2.4.49-7ubuntu4" -> (2, 4, 49).

    Only the leading dotted-numeric run is used: CPE version-range bounds
    published by NVD (versionStartIncluding etc.) are themselves plain
    dotted-numeric strings, so a distro/vendor suffix on the *detected*
    banner version (e.g. "p2", "-7ubuntu4") has nothing to compare against
    and is intentionally dropped rather than guessed at. Returns None if no
    leading numeric version could be extracted at all - callers must treat
    None as "can't compare", never as a match.
    """
    if not version:
        return None
    match = _VERSION_NUMERIC_RE.match(version.strip())
    if not match:
        return None
    return tuple(int(part) for part in match.group(0).split("."))


def _compare_version_tuples(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    """Compare two version tuples, right-padding the shorter with zeros."""
    length = max(len(a), len(b))
    a_padded = a + (0,) * (length - len(a))
    b_padded = b + (0,) * (length - len(b))
    if a_padded < b_padded:
        return -1
    if a_padded > b_padded:
        return 1
    return 0


def _extract_configurations(cve: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Flatten NVD's nested configuration nodes while preserving every CPE
    match. Boolean prerequisites are intentionally not evaluated here:
    this data is used only for product/version evidence, never as a complete
    determination that the target satisfies the CVE configuration.
    """
    configurations: list[dict[str, Any]] = []

    def visit_node(node: Any, matches: list[dict[str, Any]]) -> None:
        if not isinstance(node, dict):
            return
        for cpe_match in node.get("cpeMatch") or []:
            if not isinstance(cpe_match, dict):
                continue
            matches.append({
                "criteria": cpe_match.get("criteria"),
                "vulnerable": cpe_match.get("vulnerable", True),
                "version_start_including": cpe_match.get("versionStartIncluding"),
                "version_start_excluding": cpe_match.get("versionStartExcluding"),
                "version_end_including": cpe_match.get("versionEndIncluding"),
                "version_end_excluding": cpe_match.get("versionEndExcluding"),
            })
        for child in node.get("children") or []:
            visit_node(child, matches)

    for config in cve.get("configurations") or []:
        if not isinstance(config, dict):
            continue
        cpe_matches: list[dict[str, Any]] = []
        for node in config.get("nodes") or []:
            visit_node(node, cpe_matches)
        if cpe_matches:
            configurations.append({"cpe_matches": cpe_matches})
    return configurations

# Explicit product-to-CPE mappings. Unknown products deliberately remain
# indeterminate rather than being matched by loose substring heuristics.
_CPE_PRODUCT_IDENTITIES: dict[str, set[tuple[str, str]]] = {
    "vsftpd": {("vsftpd", "vsftpd")},
    "openssh": {("openbsd", "openssh"), ("openssh", "openssh")},
    "dropbear": {("dropbear", "dropbear")},
    "proftpd": {("proftpd", "proftpd")},
    "apachehttpd": {("apache", "http_server")},
    "nginx": {("nginx", "nginx")},
    "apachetomcat": {("apache", "tomcat")},
    "samba": {("samba", "samba")},
    "mysql": {("oracle", "mysql")},
    "mariadb": {("mariadb", "mariadb")},
    "postgresql": {("postgresql", "postgresql")},
    "redis": {("redis", "redis")},
    "microsoftiis": {("microsoft", "internet_information_server")},
}


def _product_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (value or "").lower())


def _cpe_identity(criteria: str | None) -> tuple[str, str, str] | None:
    if not criteria:
        return None
    parts = criteria.split(":")
    if len(parts) < 6 or parts[0].lower() != "cpe" or parts[1] != "2.3":
        return None
    return parts[3].lower(), parts[4].lower(), parts[5]


def _cpe_version_in_range(cpe_match: dict[str, Any], detected_version: str) -> bool | None:
    """Compare a detected version with one CPE match; None means insufficient data."""
    target = _parse_version_tuple(detected_version)
    if target is None:
        return None

    criteria = _cpe_identity(cpe_match.get("criteria"))
    cpe_version = criteria[2] if criteria else "*"
    has_bound = False
    for key in (
        "version_start_including",
        "version_start_excluding",
        "version_end_including",
        "version_end_excluding",
    ):
        raw_bound = cpe_match.get(key)
        if raw_bound is None:
            continue
        has_bound = True
        parsed_bound = _parse_version_tuple(str(raw_bound))
        if parsed_bound is None:
            return None
        comparison = _compare_version_tuples(target, parsed_bound)
        if key == "version_start_including" and comparison < 0:
            return False
        if key == "version_start_excluding" and comparison <= 0:
            return False
        if key == "version_end_including" and comparison > 0:
            return False
        if key == "version_end_excluding" and comparison >= 0:
            return False

    if has_bound:
        return True

    # When NVD supplies an exact CPE version, use it. Wildcard/ANY versions
    # without explicit range bounds cannot establish applicability.
    if cpe_version not in {"*", "-", ""}:
        exact = _parse_version_tuple(cpe_version)
        if exact is None:
            return None
        return _compare_version_tuples(target, exact) == 0
    return None


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
        "configurations": _extract_configurations(cve),
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

    def cve_affects_version(self, cve_id: str, version: str) -> bool | None:
        """
        Determine whether `version` falls inside a CPE version range NVD
        published for `cve_id`.

        This is the piece a CVE *reference* match (shared identifier
        between a Metasploit module and an NVD keyword search) cannot tell
        you: a reference overlap says "these two things both mention
        CVE-X", not "the version in front of you is inside CVE-X's
        affected range". This method reads NVD's own structured CPE
        version-range data (versionStartIncluding/Excluding,
        versionEndIncluding/Excluding) and does the comparison directly.

        Returns:
          True  - `version` falls within at least one vulnerable CPE
                  match's published range.
          False - NVD published range data for this CVE and `version`
                  falls outside every range found.
          None  - indeterminate. NVD has no record for this CVE, no
                  version-range data was published for it (e.g. only
                  exact-version CPE strings with no bounds), or `version`
                  could not be parsed as a dotted numeric version. Callers
                  must never treat None as a match.
        """
        record = self.get_cve(cve_id)
        if record is None:
            return None

        target = _parse_version_tuple(version)
        if target is None:
            return None

        configurations = record.get("configurations") or []
        checked_any_range = False
        for node in configurations:
            for cpe_match in node.get("cpe_matches", []):
                if not cpe_match.get("vulnerable", True):
                    continue
                start_inc = cpe_match.get("version_start_including")
                start_exc = cpe_match.get("version_start_excluding")
                end_inc = cpe_match.get("version_end_including")
                end_exc = cpe_match.get("version_end_excluding")
                if not any((start_inc, start_exc, end_inc, end_exc)):
                    # An exact-version (unranged) CPE match. We don't parse
                    # the version back out of the CPE criteria string here,
                    # so this match contributes no usable range evidence.
                    continue

                checked_any_range = True
                in_range = True

                if start_inc is not None:
                    bound = _parse_version_tuple(start_inc)
                    if bound is not None and _compare_version_tuples(target, bound) < 0:
                        in_range = False
                if in_range and start_exc is not None:
                    bound = _parse_version_tuple(start_exc)
                    if bound is not None and _compare_version_tuples(target, bound) <= 0:
                        in_range = False
                if in_range and end_inc is not None:
                    bound = _parse_version_tuple(end_inc)
                    if bound is not None and _compare_version_tuples(target, bound) > 0:
                        in_range = False
                if in_range and end_exc is not None:
                    bound = _parse_version_tuple(end_exc)
                    if bound is not None and _compare_version_tuples(target, bound) >= 0:
                        in_range = False

                if in_range:
                    return True

        if not checked_any_range:
            return None
        return False


    def assess_product_version(self, cve_id: str, product: str, version: str) -> str:
        """
        Assess whether an NVD vulnerable CPE entry identifies this known
        product and whether its exact version/range includes the detected
        version. This is CPE applicability evidence, not proof of a live
        vulnerability; NVD configuration prerequisites and target state may
        require additional verification.

        Returns affected, not_affected, or indeterminate.
        """
        identities = _CPE_PRODUCT_IDENTITIES.get(_product_key(product))
        if not identities or not version or version.lower() == "unknown":
            return "indeterminate"

        record = self.get_cve(cve_id)
        if record is None:
            return "indeterminate"

        matched_product = False
        saw_indeterminate_range = False
        saw_comparable_range = False
        for config in record.get("configurations") or []:
            for node in config.get("cpe_matches", []):
                if not node.get("vulnerable", True):
                    continue
                identity = _cpe_identity(node.get("criteria"))
                if identity is None or (identity[0], identity[1]) not in identities:
                    continue
                matched_product = True
                result = _cpe_version_in_range(node, version)
                if result is True:
                    return "affected"
                if result is False:
                    saw_comparable_range = True
                else:
                    saw_indeterminate_range = True

        if not matched_product:
            return "indeterminate"
        if saw_indeterminate_range or not saw_comparable_range:
            return "indeterminate"
        return "not_affected"

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
