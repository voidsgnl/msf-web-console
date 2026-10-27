import asyncio

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from app.msf_rpc import rpc, MsfRpcError
from app.security import origin_is_allowed

router = APIRouter(prefix="/api/sessions", tags=["sessions"])

POLL_INTERVAL = 0.3


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


def _find_session_info(session_id: int) -> dict | None:
    """
    session.list keys sessions by id, but msgpack hands those keys back as
    whatever type they were packed as (often int, sometimes str depending
    on the msfrpcd version) - so check both rather than assuming one.
    """
    sessions = rpc.call("session.list")
    return sessions.get(session_id) or sessions.get(str(session_id))


@router.websocket("/ws/{session_id}")
async def session_ws(websocket: WebSocket, session_id: int):
    """
    Interactive bridge to a live session (shell or meterpreter), the same
    poll-and-relay pattern as the msfconsole WebSocket in console.py.

    Shell and meterpreter sessions use different RPC method pairs
    (session.shell_write/read vs session.meterpreter_write/read) - which
    pair to use is picked once at connect time based on the session's
    reported type, since msfrpcd has no single generic "write/read" call
    that works for both.
    """
    origin = websocket.headers.get("origin")
    if not origin_is_allowed(origin):
        await websocket.close(code=1008, reason="Origin not allowed.")
        return

    await websocket.accept()

    try:
        info = _find_session_info(session_id)
        if info is None:
            await websocket.send_json(
                {"type": "error", "data": f"Session {session_id} not found (it may have closed)."}
            )
            return

        session_type = info.get("type", "shell")
        is_meterpreter = session_type == "meterpreter"
        write_method = "session.meterpreter_write" if is_meterpreter else "session.shell_write"
        read_method = "session.meterpreter_read" if is_meterpreter else "session.shell_read"

        await websocket.send_json({"type": "ready", "session_type": session_type})

        async def reader():
            while True:
                await asyncio.sleep(POLL_INTERVAL)
                try:
                    result = rpc.call(read_method, session_id)
                except MsfRpcError as exc:
                    await websocket.send_json({"type": "error", "data": str(exc)})
                    return
                # shell_read/meterpreter_read both return {"data": "..."}, but
                # guard for a bare-string response just in case.
                data = result.get("data") if isinstance(result, dict) else result
                if data:
                    await websocket.send_json({"type": "output", "data": data})

        async def writer():
            while True:
                msg = await websocket.receive_json()
                if msg.get("type") == "input":
                    try:
                        rpc.call(write_method, session_id, msg["data"])
                    except MsfRpcError as exc:
                        await websocket.send_json({"type": "error", "data": str(exc)})
                        return

        # Stop the other half of the bridge whenever either direction ends.
        # In particular, a reader error must not leave writer() waiting forever
        # on receive_json(), and a disconnected browser must stop the poll loop.
        tasks = {
            asyncio.create_task(reader()),
            asyncio.create_task(writer()),
        }
        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

            for task in done:
                try:
                    task.result()
                except WebSocketDisconnect:
                    pass
                except MsfRpcError as exc:
                    await websocket.send_json({"type": "error", "data": str(exc)})
                except Exception as exc:
                    # The browser may already be gone; do not let an error
                    # while sending a diagnostic keep the connection alive.
                    try:
                        await websocket.send_json({"type": "error", "data": str(exc)})
                    except Exception:
                        pass
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    except WebSocketDisconnect:
        pass
    except MsfRpcError as exc:
        await websocket.send_json({"type": "error", "data": str(exc)})
