import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.msf_rpc import rpc, MsfRpcError

router = APIRouter(prefix="/api/console", tags=["console"])

POLL_INTERVAL = 0.3


@router.websocket("/ws")
async def console_ws(websocket: WebSocket):
    """
    Opens a fresh msfconsole instance via console.create, then bridges it to
    the browser: client -> console.write, console.read polled -> client.
    One WebSocket connection = one console.
    """
    await websocket.accept()
    console_id = None
    try:
        created = rpc.call("console.create")
        console_id = created["id"]
        await websocket.send_json({"type": "ready", "console_id": console_id})

        # Drain the initial banner
        initial = rpc.call("console.read", console_id)
        if initial.get("data"):
            await websocket.send_json({"type": "output", "data": initial["data"]})

        async def reader():
            while True:
                await asyncio.sleep(POLL_INTERVAL)
                try:
                    result = rpc.call("console.read", console_id)
                except MsfRpcError as exc:
                    await websocket.send_json({"type": "error", "data": str(exc)})
                    break
                if result.get("data"):
                    await websocket.send_json({"type": "output", "data": result["data"]})
                if result.get("busy"):
                    await websocket.send_json({"type": "status", "busy": True})

        async def writer():
            while True:
                msg = await websocket.receive_json()
                if msg.get("type") == "input":
                    rpc.call("console.write", console_id, msg["data"])

        await asyncio.gather(reader(), writer())

    except WebSocketDisconnect:
        pass
    except MsfRpcError as exc:
        await websocket.send_json({"type": "error", "data": str(exc)})
    finally:
        if console_id is not None:
            try:
                rpc.call("console.destroy", console_id)
            except MsfRpcError:
                pass
