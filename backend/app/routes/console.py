import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.msf_rpc import rpc, MsfRpcError
from app.security import origin_is_allowed

router = APIRouter(prefix="/api/console", tags=["console"])

POLL_INTERVAL = 0.3


@router.websocket("/ws")
async def console_ws(websocket: WebSocket):
    """
    Opens a fresh msfconsole instance via console.create, then bridges it to
    the browser: client -> console.write, console.read polled -> client.
    One WebSocket connection = one console.
    """
    origin = websocket.headers.get("origin")
    if not origin_is_allowed(origin):
        await websocket.close(code=1008, reason="Origin not allowed.")
        return

    await websocket.accept()
    console_id = None

    # msfrpcd returns the current prompt (e.g. "msf6 > ") as a field
    # separate from "data" - it is never embedded in the output text.
    # Without forwarding it, the terminal never shows where you're meant
    # to type, so it doesn't read as a live console even though it is one.
    #
    # The prompt string is usually *identical* between commands (it only
    # changes on context switches like `use some/module`), so we can't key
    # off "did the text change" - we have to key off "did the console just
    # become idle again after running something". `awaiting_prompt` is set
    # whenever we submit input and cleared the next time a read reports
    # not-busy, at which point we emit whatever the latest known prompt
    # text is (tracked separately since a given poll may omit "prompt"
    # even while idle).
    awaiting_prompt = True
    last_known_prompt: str | None = None

    async def observe(result: dict):
        nonlocal awaiting_prompt, last_known_prompt
        if result.get("prompt"):
            last_known_prompt = result["prompt"]
        if awaiting_prompt and not result.get("busy") and last_known_prompt:
            await websocket.send_json({"type": "prompt", "data": last_known_prompt})
            awaiting_prompt = False

    try:
        created = rpc.call("console.create")
        console_id = created["id"]
        await websocket.send_json({"type": "ready", "console_id": console_id})

        # Style every new console with a Starship-like prompt (colored "msf"
        # label + a colored arrow instead of the default plain ">") rather
        # than the bare "msf6 > " msfconsole ships with. %grn/%clr are
        # Metasploit's own prompt color tokens. These are real `set`
        # commands against framework datastore options (Prompt/PromptChar),
        # so they're silent on success - nothing visible lands in the
        # banner, just the applied style on the next prompt render.
        rpc.call("console.write", console_id, "set PROMPT %grnmsf%clr\n")
        rpc.call("console.write", console_id, "set PromptChar %grn❯%clr\n")
        await asyncio.sleep(0.3)  # let msfrpcd process both `set` commands

        # Drain the initial banner
        initial = rpc.call("console.read", console_id)
        if initial.get("data"):
            await websocket.send_json({"type": "output", "data": initial["data"]})
        await observe(initial)

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
                await observe(result)

        async def writer():
            nonlocal awaiting_prompt
            while True:
                msg = await websocket.receive_json()
                if msg.get("type") == "input":
                    rpc.call("console.write", console_id, msg["data"])
                    # A command was just submitted - the next idle read
                    # should re-display the prompt, even if its text is
                    # unchanged from before.
                    awaiting_prompt = True

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
