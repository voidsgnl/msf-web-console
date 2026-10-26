from fastapi import APIRouter, HTTPException

from app.msf_rpc import rpc, MsfRpcError

router = APIRouter(prefix="/api/jobs", tags=["jobs"])


@router.get("")
def list_jobs():
    try:
        return rpc.call("job.list")
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))


@router.get("/{job_id}/info")
def job_info(job_id: str):
    try:
        return rpc.call("job.info", job_id)
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))


@router.post("/{job_id}/stop")
def stop_job(job_id: str):
    try:
        return rpc.call("job.stop", job_id)
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))
