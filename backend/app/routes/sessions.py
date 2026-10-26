from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.msf_rpc import rpc, MsfRpcError

router = APIRouter(prefix="/api/sessions", tags=["sessions"])


@router.get("")
def list_sessions():
    try:
        return rpc.call("session.list")
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))


class WriteRequest(BaseModel):
    data: str


@router.post("/{session_id}/write")
def write_session(session_id: int, req: WriteRequest):
    try:
        return rpc.call("session.shell_write", session_id, req.data)
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))


@router.get("/{session_id}/read")
def read_session(session_id: int):
    try:
        return rpc.call("session.shell_read", session_id)
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))


@router.post("/{session_id}/stop")
def stop_session(session_id: int):
    try:
        return rpc.call("session.stop", session_id)
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))
