import hashlib
import hmac
import os
import secrets
import threading
import time
from http.cookies import SimpleCookie
from typing import Any


SESSION_COOKIE_NAME = "msf_web_session"
MIN_PASSWORD_LENGTH = 12
DEFAULT_SESSION_TTL_SECONDS = 8 * 60 * 60
_PLACEHOLDER_PASSWORDS = {
    "changeme",
    "change-me",
    "replace-with-a-long-random-password",
    "your-password-here",
}


class AuthenticationNotConfigured(Exception):
    pass


def session_ttl_seconds() -> int:
    raw = os.getenv("MSF_WEB_SESSION_TTL_SECONDS", str(DEFAULT_SESSION_TTL_SECONDS))
    try:
        ttl = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_SESSION_TTL_SECONDS
    return min(max(ttl, 300), 7 * 24 * 60 * 60)


def cookie_secure() -> bool:
    return os.getenv("MSF_WEB_COOKIE_SECURE", "false").strip().lower() in {"1", "true", "yes", "on"}


def configured_credentials() -> tuple[str, str] | None:
    username = os.getenv("MSF_WEB_USERNAME", "").strip()
    password = os.getenv("MSF_WEB_PASSWORD", "")
    if (
        not username
        or len(password) < MIN_PASSWORD_LENGTH
        or password.strip().lower() in _PLACEHOLDER_PASSWORDS
    ):
        return None
    return username, password


def authentication_configured() -> bool:
    return configured_credentials() is not None


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def cookie_token_from_scope(scope: dict[str, Any]) -> str | None:
    cookie_header = next(
        (value.decode("latin-1") for key, value in scope.get("headers", []) if key.lower() == b"cookie"),
        "",
    )
    try:
        cookies = SimpleCookie()
        cookies.load(cookie_header)
        morsel = cookies.get(SESSION_COOKIE_NAME)
        return morsel.value if morsel else None
    except Exception:
        return None


class SessionStore:
    """Opaque, expiring server-side sessions. Only token hashes are retained."""

    def __init__(self):
        self._lock = threading.Lock()
        self._sessions: dict[str, tuple[str, float]] = {}

    def create(self, username: str) -> str:
        token = secrets.token_urlsafe(32)
        expires = time.time() + session_ttl_seconds()
        with self._lock:
            self._purge_expired_locked()
            self._sessions[_token_digest(token)] = (username, expires)
        return token

    def username_for(self, token: str | None) -> str | None:
        if not token:
            return None
        digest = _token_digest(token)
        now = time.time()
        with self._lock:
            entry = self._sessions.get(digest)
            if entry is None:
                return None
            username, expires = entry
            if expires <= now:
                self._sessions.pop(digest, None)
                return None
            return username

    def revoke(self, token: str | None) -> None:
        if not token:
            return
        with self._lock:
            self._sessions.pop(_token_digest(token), None)

    def _purge_expired_locked(self) -> None:
        now = time.time()
        expired = [digest for digest, (_, expires) in self._sessions.items() if expires <= now]
        for digest in expired:
            self._sessions.pop(digest, None)

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()


sessions = SessionStore()


def authenticate_credentials(username: str, password: str) -> str | None:
    configured = configured_credentials()
    if configured is None:
        raise AuthenticationNotConfigured(
            "Authentication is not configured. Set MSF_WEB_USERNAME and a strong MSF_WEB_PASSWORD in backend/.env, then restart the backend."
        )
    expected_username, expected_password = configured
    username_matches = hmac.compare_digest(username.encode("utf-8"), expected_username.encode("utf-8"))
    password_matches = hmac.compare_digest(password.encode("utf-8"), expected_password.encode("utf-8"))
    if username_matches and password_matches:
        return expected_username
    return None
