import asyncio
import unittest
from unittest.mock import patch

from app.msf_rpc import MsfRpcError
from app.routes.sessions import session_ws


class FakeWebSocket:
    def __init__(self, incoming=None):
        self.headers = {}
        self.messages = []
        self.incoming = list(incoming or [])
        self.waiting_cancelled = False
        self.accepted = False
        self._never = asyncio.Event()

    async def accept(self):
        self.accepted = True

    async def send_json(self, data):
        self.messages.append(data)

    async def receive_json(self):
        if self.incoming:
            return self.incoming.pop(0)
        try:
            await self._never.wait()
        finally:
            self.waiting_cancelled = True


class SessionWebSocketLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_reader_rpc_error_cancels_waiting_writer(self):
        websocket = FakeWebSocket()

        def rpc_call(method, *args):
            if method == "session.list":
                return {1: {"type": "shell"}}
            if method == "session.shell_read":
                raise MsfRpcError("session has closed")
            self.fail(f"Unexpected RPC method: {method}")

        with (
            patch("app.routes.sessions.rpc.call", side_effect=rpc_call),
            patch("app.routes.sessions.POLL_INTERVAL", 0.001),
        ):
            await session_ws(websocket, 1)

        self.assertTrue(websocket.accepted)
        self.assertTrue(websocket.waiting_cancelled)
        self.assertIn(
            {"type": "error", "data": "session has closed"},
            websocket.messages,
        )

    async def test_writer_rpc_error_ends_both_directions(self):
        websocket = FakeWebSocket([{"type": "input", "data": "whoami\n"}])

        def rpc_call(method, *args):
            if method == "session.list":
                return {1: {"type": "shell"}}
            if method == "session.shell_write":
                raise MsfRpcError("session write failed")
            if method == "session.shell_read":
                return {"data": ""}
            self.fail(f"Unexpected RPC method: {method}")

        with (
            patch("app.routes.sessions.rpc.call", side_effect=rpc_call),
            patch("app.routes.sessions.POLL_INTERVAL", 5),
        ):
            await asyncio.wait_for(session_ws(websocket, 1), timeout=1)

        self.assertIn(
            {"type": "error", "data": "session write failed"},
            websocket.messages,
        )


if __name__ == "__main__":
    unittest.main()
