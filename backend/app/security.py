import ipaddress
import os
from urllib.parse import urlsplit

from fastapi.responses import JSONResponse
from starlette.responses import Response

from app.authentication import authentication_configured, cookie_token_from_scope, sessions


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
                    "Remote access is not supported by this local-only application."
                )
            },
            headers={"Cache-Control": "no-store"},
        )
        await response(scope, receive, send)


class AuthenticationMiddleware:
    """Require a valid server-side session for HTTP endpoints and WebSockets."""

    OPEN_HTTP_PATHS = {
        ("/api/auth/login", "POST"),
        ("/api/auth/session", "GET"),
    }

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        scope_type = scope.get("type")
        if scope_type not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }
        origin = headers.get("origin")
        if origin and not origin_is_allowed(origin):
            if scope_type == "websocket":
                await send({
                    "type": "websocket.close",
                    "code": 4403,
                    "reason": "Browser origin not allowed.",
                })
            else:
                response = JSONResponse(
                    status_code=403,
                    content={"detail": "Browser origin not allowed."},
                    headers={"Cache-Control": "no-store"},
                )
                await response(scope, receive, send)
            return

        if scope_type == "http":
            method = scope.get("method", "GET").upper()
            if method == "OPTIONS" or (path, method) in self.OPEN_HTTP_PATHS:
                await self.app(scope, receive, send)
                return

        if not authentication_configured():
            detail = (
                "Web console login is not configured. Set MSF_WEB_USERNAME and a strong "
                "MSF_WEB_PASSWORD (at least 12 characters) in backend/.env, then restart the backend."
            )
            if scope_type == "websocket":
                await send({
                    "type": "websocket.close",
                    "code": 4403,
                    "reason": "Web console authentication is not configured.",
                })
                return
            response = JSONResponse(
                status_code=503,
                content={"detail": detail},
                headers={"Cache-Control": "no-store"},
            )
            await response(scope, receive, send)
            return

        username = sessions.username_for(cookie_token_from_scope(scope))
        if username is None:
            if scope_type == "websocket":
                await send({
                    "type": "websocket.close",
                    "code": 4401,
                    "reason": "Login required or session expired.",
                })
                return
            response = JSONResponse(
                status_code=401,
                content={"detail": "Login required or session expired."},
                headers={"Cache-Control": "no-store"},
            )
            await response(scope, receive, send)
            return

        scope.setdefault("state", {})["authenticated_user"] = username
        await self.app(scope, receive, send)
