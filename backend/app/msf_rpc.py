"""
Thin client for the Metasploit msfrpcd JSON/MessagePack-RPC API.

msfrpcd exposes its API over HTTP(S) at POST /api/1.0, where the request
and response bodies are MessagePack-encoded arrays: [method, *params].
This mirrors the protocol used by msfconsole's own RPC plugin and by
libraries like pymetasploit3, implemented here directly with `requests`
and `msgpack` so we have no extra runtime dependencies beyond those two.

Reference: https://docs.metasploit.com/docs/using-metasploit/advanced/RPC.html
"""
from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any

import msgpack
import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


def _decode_bytes(obj: Any) -> Any:
    """
    Ruby's msgpack gem encodes strings in a way that Python's msgpack
    (even with raw=False) sometimes still hands back as raw bytes rather
    than str, depending on how the key/value was packed on the Metasploit
    side. We recursively decode everything that looks like UTF-8 text so
    the rest of the client can compare against plain Python strings
    ("result" == "success") instead of silently failing on a bytes/str
    mismatch (b"result" != "result").
    """
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8")
        except UnicodeDecodeError:
            return obj  # genuinely binary payload (e.g. screenshot/loot data) - leave as-is
    if isinstance(obj, dict):
        return {_decode_bytes(k): _decode_bytes(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_decode_bytes(v) for v in obj]
    return obj


class MsfRpcError(Exception):
    def __init__(self, message: str, error_code: Any = None, error_message: Any = None):
        super().__init__(message)
        self.error_code = error_code
        self.error_message = error_message


class MsfRpcClient:
    """
    Minimal synchronous msfrpcd client. One instance is shared across the
    FastAPI app; `token` is re-used for every call after login and
    re-established automatically if the server reports an auth failure.
    """

    def __init__(self):
        self.host = os.getenv("MSF_RPC_HOST", "127.0.0.1")
        self.port = int(os.getenv("MSF_RPC_PORT", "55553"))
        self.user = os.getenv("MSF_RPC_USER", "msf")
        self.password = os.getenv("MSF_RPC_PASS", "")
        use_ssl = os.getenv("MSF_RPC_SSL", "true").lower() != "false"
        verify = os.getenv("MSF_RPC_VERIFY_CERT", "false").lower() == "true"
        scheme = "https" if use_ssl else "http"
        self.base_url = f"{scheme}://{self.host}:{self.port}/api/1.0"
        self.verify = verify
        self.token: str | None = None
        self._lock = threading.Lock()

    # -- low level -----------------------------------------------------

    @staticmethod
    def _rpc_error_message(decoded: dict[str, Any], method: str) -> str:
        """Extract a useful RPC error without exposing the server backtrace."""
        candidates = (
            decoded.get("error_message"),
            decoded.get("error_string"),
            decoded.get("message"),
        )
        message = None
        generic_messages = {"unknown rpc error", "unknown error"}
        for candidate in candidates:
            if candidate is None:
                continue
            value = str(candidate).strip()
            if value and value.lower() not in generic_messages:
                message = value
                break

        if message is None:
            message = f"Metasploit RPC method '{method}' returned an error without details."

        error_class = decoded.get("error_class")
        if error_class and not message.startswith(f"{error_class}:"):
            message = f"{error_class}: {message}"

        error_code = decoded.get("error_code")
        if error_code is not None:
            message = f"{message} (RPC error code {error_code})"

        # Keep an unexpected server-supplied message from overwhelming the UI.
        return message[:1000]

    def _raw_call(self, method: str, params: list[Any]) -> Any:
        body = msgpack.packb([method] + params, use_bin_type=True)
        try:
            resp = requests.post(
                self.base_url,
                data=body,
                headers={"Content-Type": "binary/message-pack"},
                verify=self.verify,
                timeout=120,
            )
        except requests.exceptions.ConnectionError as exc:
            raise MsfRpcError(
                f"Could not reach msfrpcd at {self.host}:{self.port}. "
                "Is msfrpcd running? See backend/.env.example for the start command."
            ) from exc

        # Metasploit normally returns MessagePack even for RPC exceptions,
        # including non-200 HTTP responses. Decode that body before falling back
        # to the HTTP status text so we do not hide error_string/error_class.
        try:
            decoded = _decode_bytes(
                msgpack.unpackb(resp.content, raw=False, strict_map_key=False)
            )
        except Exception as exc:
            if resp.status_code != 200:
                raise MsfRpcError(
                    f"msfrpcd HTTP {resp.status_code}: {resp.text[:300]}"
                ) from exc
            raise MsfRpcError(
                f"msfrpcd returned an invalid MessagePack response for {method}."
            ) from exc

        if isinstance(decoded, dict) and decoded.get("error"):
            error_message = self._rpc_error_message(decoded, method)
            if resp.status_code != 200:
                error_message = f"{error_message} (HTTP {resp.status_code})"
            # decoded may omit error_message/error_string entirely (this is what
            # produces the generic "returned an error without details" text the
            # client sees) - log the full raw payload server-side so the actual
            # error_class / whatever fields msfrpcd did send are still visible.
            logger.error(
                "msfrpcd error for method %r (HTTP %s): raw response=%r",
                method, resp.status_code, decoded,
            )
            raise MsfRpcError(
                error_message,
                error_code=decoded.get("error_code"),
                error_message=error_message,
            )

        if resp.status_code != 200:
            raise MsfRpcError(f"msfrpcd HTTP {resp.status_code}: {resp.text[:300]}")
        return decoded

    def call(self, method: str, *params: Any) -> Any:
        """Authenticated call. Logs in on first use and re-logs-in once on auth failure."""
        with self._lock:
            if self.token is None and method != "auth.login":
                self._login()
            try:
                return self._raw_call(method, [self.token, *params] if method != "auth.login" else list(params))
            except MsfRpcError as exc:
                if "auth" in str(exc.error_message or "").lower() and method != "auth.login":
                    self._login()
                    return self._raw_call(method, [self.token, *params])
                raise

    def _login(self):
        result = self._raw_call("auth.login", [self.user, self.password])
        if result.get("result") != "success":
            raise MsfRpcError("msfrpcd login failed: check MSF_RPC_USER/MSF_RPC_PASS in .env")
        self.token = result["token"]

    def is_connected(self) -> bool:
        try:
            self.call("core.version")
            return True
        except MsfRpcError:
            return False


# Shared singleton used by the FastAPI routes
rpc = MsfRpcClient()
