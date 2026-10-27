import threading
import time
from collections import deque
from typing import Deque

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field

from app.authentication import (
    SESSION_COOKIE_NAME,
    AuthenticationNotConfigured,
    authenticate_credentials,
    authentication_configured,
    cookie_secure,
    configured_credentials,
    session_ttl_seconds,
    sessions,
)

router = APIRouter(prefix="/api/auth", tags=["authentication"])

MAX_FAILED_LOGINS = 5
LOGIN_WINDOW_SECONDS = 5 * 60
_login_lock = threading.Lock()
_failed_logins: dict[str, Deque[float]] = {}


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=1024)


def _client_key(request: Request) -> str:
    # Never trust X-Forwarded-For: this service is local-only and does not
    # support proxy-based remote access.
    return request.client.host if request.client else "unknown"


def _check_login_rate_limit(client: str) -> None:
    now = time.monotonic()
    with _login_lock:
        attempts = _failed_logins.setdefault(client, deque())
        while attempts and now - attempts[0] >= LOGIN_WINDOW_SECONDS:
            attempts.popleft()
        if len(attempts) >= MAX_FAILED_LOGINS:
            retry_after = max(1, int(LOGIN_WINDOW_SECONDS - (now - attempts[0])))
            raise HTTPException(
                status_code=429,
                detail="Too many failed login attempts. Wait before trying again.",
                headers={"Retry-After": str(retry_after), "Cache-Control": "no-store"},
            )


def _record_failed_login(client: str) -> None:
    now = time.monotonic()
    with _login_lock:
        attempts = _failed_logins.setdefault(client, deque())
        while attempts and now - attempts[0] >= LOGIN_WINDOW_SECONDS:
            attempts.popleft()
        attempts.append(now)


def _clear_failed_logins(client: str) -> None:
    with _login_lock:
        _failed_logins.pop(client, None)


@router.get("/session")
def session_status(request: Request, response: Response):
    """Public bootstrap endpoint; reports auth setup without disclosing a password."""
    response.headers["Cache-Control"] = "no-store"
    configured = authentication_configured()
    token = request.cookies.get(SESSION_COOKIE_NAME)
    username = sessions.username_for(token) if configured else None
    return {
        "configured": configured,
        "authenticated": username is not None,
        "username": username,
    }


@router.post("/login")
def login(req: LoginRequest, request: Request, response: Response):
    client = _client_key(request)
    _check_login_rate_limit(client)
    try:
        username = authenticate_credentials(req.username, req.password)
    except AuthenticationNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc), headers={"Cache-Control": "no-store"})

    if username is None:
        _record_failed_login(client)
        # A uniform message avoids disclosing whether the username exists.
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password.",
            headers={"Cache-Control": "no-store"},
        )

    _clear_failed_logins(client)
    token = sessions.create(username)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=session_ttl_seconds(),
        httponly=True,
        secure=cookie_secure(),
        samesite="strict",
        path="/",
    )
    response.headers["Cache-Control"] = "no-store"
    return {"authenticated": True, "username": username}


@router.post("/logout")
def logout(request: Request, response: Response):
    sessions.revoke(request.cookies.get(SESSION_COOKIE_NAME))
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        secure=cookie_secure(),
        samesite="strict",
    )
    response.headers["Cache-Control"] = "no-store"
    return {"authenticated": False}
