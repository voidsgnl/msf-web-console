from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.msf_rpc import rpc, MsfRpcError
from app.nvd_client import CVE_ID_RE, NvdError, extract_cve_ids, nvd_client

router = APIRouter(prefix="/api/cve", tags=["cve"])


@router.get("/workspace-enrichment")
def workspace_enrichment(limit: int = 25):
    """
    Enrich CVE identifiers referenced by the active workspace's vulnerability
    records against the NVD. Capped per call to respect NVD's rate limits;
    if `remaining_cves` is non-empty, call again with the same limit to
    continue (already-looked-up CVEs are served from cache, so later pages
    cost nothing extra for CVEs already seen).
    """
    if not 1 <= limit <= 50:
        raise HTTPException(400, "limit must be between 1 and 50.")

    try:
        result = rpc.call("db.vulns", {})
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))

    records = result.get("vulns", []) if isinstance(result, dict) else []

    cve_to_records: dict[str, list[dict[str, object]]] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        for cve_id in extract_cve_ids(record):
            cve_to_records.setdefault(cve_id, []).append(
                {"host": record.get("host"), "name": record.get("name")}
            )

    all_cve_ids = sorted(cve_to_records)
    page = all_cve_ids[:limit]
    remaining = all_cve_ids[limit:]

    enriched: dict[str, dict | None] = {}
    errors: dict[str, str] = {}
    for cve_id in page:
        try:
            enriched[cve_id] = nvd_client.get_cve(cve_id)
        except NvdError as exc:
            errors[cve_id] = str(exc)

    return {
        "total_cves_found": len(all_cve_ids),
        "enriched": enriched,
        "errors": errors,
        "matched_records": {cve_id: cve_to_records[cve_id] for cve_id in page},
        "remaining_cves": remaining,
    }


@router.get("/{cve_id}")
def lookup_cve(cve_id: str):
    """Look up a single CVE identifier against the NVD."""
    if not CVE_ID_RE.fullmatch(cve_id.strip()):
        raise HTTPException(400, "cve_id must look like CVE-YYYY-NNNN.")
    try:
        result = nvd_client.get_cve(cve_id)
    except NvdError as exc:
        raise HTTPException(502, str(exc))
    if result is None:
        raise HTTPException(404, f"{cve_id.upper()} was not found in the NVD.")
    return result
