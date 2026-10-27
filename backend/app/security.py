import ipaddress
import os
from urllib.parse import urlsplit

from fastapi.responses import JSONResponse


DEFAULT_WEB_ORIGINS = (
    "http://localhost:5173",
    "http://127.0.0.1:5173",
)
DEFAULT_ALLOWED_HOSTS = (
    "localhost",
    "127.0.0.1",
    "::1",
)


def _csv_env(name: str, default: tuple[str, ...]) -> list[str]:
    raw = os.getenv(name)
    if raw is None:
        return list(default)
    return [value.strip() for value in raw.split(",") if value.strip()]


def allowed_web_origins() -> list[str]:
    """Explicit browser origins allowed to call the local web console."""
    return [origin.rstrip("/") for origin in _csv_env("MSF_WEB_CORS_ORIGINS", DEFAULT_WEB_ORIGINS)]


def allowed_hosts() -> list[str]:
    """Allowed Host header values; never use '*' for this local console."""
    return _csv_env("MSF_WEB_ALLOWED_HOSTS", DEFAULT_ALLOWED_HOSTS)


def origin_is_allowed(origin: str | None) -> bool:
    """
    Protect browser WebSockets against cross-site WebSocket hijacking.
    Requests without an Origin header are allowed for non-browser local tools;
    the local-client middleware and Host validation still apply.
    """
    if not origin:
        return True
    try:
        parsed = urlsplit(origin)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.path not in {"", "/"}:
            return False
        normalized = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
    except ValueError:
        return False
    return normalized in {value.lower() for value in allowed_web_origins()}


def is_loopback_client(client_host: str | None) -> bool:
    """Only permit loopback client addresses by default."""
    if not client_host:
        return False
    try:
        return ipaddress.ip_address(client_host).is_loopback
    except ValueError:
        return False


class LocalOnlyMiddleware:
    """
    Defense-in-depth local-client guard, even if Uvicorn is accidentally bound
    to 0.0.0.0. This is not a substitute for authentication behind a reverse
    proxy; do not expose or proxy this console to remote users.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return

        client = scope.get("client")
        client_host = client[0] if client else None
        if is_loopback_client(client_host):
            await self.app(scope, receive, send)
            return

        if scope["type"] == "websocket":
            await send({
                "type": "websocket.close",
                "code": 1008,
                "reason": "MSF Web Console accepts local connections only.",
            })
            return

        response = JSONResponse(
            status_code=403,
            content={
                "detail": (
                    "MSF Web Console accepts local connections only. "
                    "Remote access is not supported because this application has no user authentication."
                )
            },
            headers={"Cache-Control": "no-store"},
        )
        await response(scope, receive, send)
