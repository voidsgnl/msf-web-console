import asyncio
import os
import unittest
from unittest.mock import patch

from app.authentication import (
    AuthenticationNotConfigured,
    authenticate_credentials,
    authentication_configured,
    configured_credentials,
    sessions,
)
from fastapi import HTTPException, Response
from starlette.requests import Request

from app.routes.auth import LoginRequest, login, logout, session_status, _failed_logins
from app.security import AuthenticationMiddleware


class AuthenticationConfigurationTests(unittest.TestCase):
    def setUp(self):
        sessions.clear()
        _failed_logins.clear()

    def tearDown(self):
        sessions.clear()
        _failed_logins.clear()

    def request(self, path, method="GET", cookie=None, client=("127.0.0.1", 43210)):
        headers = []
        if cookie:
            headers.append((b"cookie", cookie.encode("latin-1")))
        return Request({
            "type": "http",
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": headers,
            "client": client,
            "server": ("localhost", 5173),
            "asgi": {"version": "3.0", "spec_version": "2.3"},
        })

    def test_missing_credentials_fail_closed(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("MSF_WEB_USERNAME", None)
            os.environ.pop("MSF_WEB_PASSWORD", None)
            self.assertFalse(authentication_configured())
            self.assertIsNone(configured_credentials())
            with self.assertRaises(AuthenticationNotConfigured):
                authenticate_credentials("admin", "a-long-password-here")

    def test_short_or_placeholder_password_is_not_accepted_as_configuration(self):
        for password in ("tiny", "replace-with-a-long-random-password", "changeme"):
            with self.subTest(password=password):
                with patch.dict(os.environ, {"MSF_WEB_USERNAME": "admin", "MSF_WEB_PASSWORD": password}):
                    self.assertFalse(authentication_configured())

    def test_credentials_are_compared_and_success_returns_configured_username(self):
        with patch.dict(os.environ, {"MSF_WEB_USERNAME": "admin", "MSF_WEB_PASSWORD": "a-long-unique-password"}):
            self.assertTrue(authentication_configured())
            self.assertEqual(authenticate_credentials("admin", "a-long-unique-password"), "admin")
            self.assertIsNone(authenticate_credentials("admin", "wrong-password-123"))
            self.assertIsNone(authenticate_credentials("other", "a-long-unique-password"))

    def test_login_sets_http_only_strict_session_cookie(self):
        with patch.dict(os.environ, {
            "MSF_WEB_USERNAME": "admin",
            "MSF_WEB_PASSWORD": "a-long-unique-password",
            "MSF_WEB_COOKIE_SECURE": "false",
            "MSF_WEB_SESSION_TTL_SECONDS": "3600",
        }):
            response = Response()
            result = login(
                LoginRequest(username="admin", password="a-long-unique-password"),
                self.request("/api/auth/login", "POST"),
                response,
            )
        self.assertEqual(result, {"authenticated": True, "username": "admin"})
        cookie = response.headers["set-cookie"].lower()
        self.assertIn("httponly", cookie)
        self.assertIn("samesite=strict", cookie)
        self.assertIn("max-age=3600", cookie)
        self.assertNotIn("secure", cookie)
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_login_invalid_credentials_have_generic_error(self):
        with patch.dict(os.environ, {
            "MSF_WEB_USERNAME": "admin",
            "MSF_WEB_PASSWORD": "a-long-unique-password",
        }):
            with self.assertRaises(HTTPException) as raised:
                login(
                    LoginRequest(username="wrong", password="wrong-password-123"),
                    self.request("/api/auth/login", "POST"),
                    Response(),
                )
        self.assertEqual(raised.exception.status_code, 401)
        self.assertEqual(raised.exception.detail, "Invalid username or password.")

    def test_login_is_blocked_until_credentials_are_configured(self):
        with patch.dict(os.environ, {"MSF_WEB_USERNAME": "", "MSF_WEB_PASSWORD": ""}):
            with self.assertRaises(HTTPException) as raised:
                login(
                    LoginRequest(username="admin", password="a-long-unique-password"),
                    self.request("/api/auth/login", "POST"),
                    Response(),
                )
        self.assertEqual(raised.exception.status_code, 503)

    def test_logout_revokes_session_and_clears_cookie(self):
        token = sessions.create("admin")
        with patch.dict(os.environ, {"MSF_WEB_COOKIE_SECURE": "false"}):
            response = Response()
            result = logout(
                self.request("/api/auth/logout", "POST", f"msf_web_session={token}"),
                response,
            )
        self.assertEqual(result, {"authenticated": False})
        self.assertIsNone(sessions.username_for(token))
        self.assertIn("max-age=0", response.headers["set-cookie"].lower())

    def test_session_status_is_not_cacheable(self):
        token = sessions.create("admin")
        with patch.dict(os.environ, {
            "MSF_WEB_USERNAME": "admin",
            "MSF_WEB_PASSWORD": "a-long-unique-password",
        }):
            response = Response()
            result = session_status(
                self.request("/api/auth/session", cookie=f"msf_web_session={token}"),
                response,
            )
        self.assertTrue(result["configured"])
        self.assertTrue(result["authenticated"])
        self.assertEqual(result["username"], "admin")
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_session_tokens_are_opaque_revocable_and_expire(self):
        with patch.dict(os.environ, {"MSF_WEB_SESSION_TTL_SECONDS": "300"}):
            with patch("app.authentication.time.time", return_value=1000):
                token = sessions.create("admin")
                self.assertNotIn(token, sessions._sessions)
                self.assertEqual(sessions.username_for(token), "admin")
            with patch("app.authentication.time.time", return_value=1301):
                self.assertIsNone(sessions.username_for(token))
                self.assertIsNone(sessions.username_for(token))

        token = sessions.create("admin")
        sessions.revoke(token)
        self.assertIsNone(sessions.username_for(token))


class AuthenticationMiddlewareTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        sessions.clear()

    def tearDown(self):
        sessions.clear()

    async def _call_middleware(self, scope, configured_env=None):
        events = []
        called = []

        async def app(inner_scope, receive, send):
            called.append(inner_scope)
            await send({"type": "http.response.start", "status": 204, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        middleware = AuthenticationMiddleware(app)

        async def send(event):
            events.append(event)

        environ = {
            "MSF_WEB_USERNAME": "admin",
            "MSF_WEB_PASSWORD": "a-long-unique-password",
            "MSF_WEB_CORS_ORIGINS": "http://localhost:5173",
        }
        environ.update(configured_env or {})
        with patch.dict(os.environ, environ):
            await middleware(scope, lambda: None, send)
        return events, called

    def http_scope(self, path="/api/modules", headers=None):
        return {
            "type": "http",
            "method": "GET",
            "path": path,
            "headers": headers or [],
            "client": ("127.0.0.1", 43210),
            "state": {},
        }

    async def test_protected_http_route_requires_session(self):
        events, called = await self._call_middleware(self.http_scope())
        self.assertFalse(called)
        self.assertEqual(events[0]["status"], 401)
        self.assertIn(b"Login required", events[1]["body"])

    async def test_valid_session_allows_protected_http_route(self):
        token = sessions.create("admin")
        cookie = f"msf_web_session={token}".encode()
        events, called = await self._call_middleware(self.http_scope(headers=[(b"cookie", cookie)]))
        self.assertEqual(len(called), 1)
        self.assertEqual(events[0]["status"], 204)
        self.assertEqual(called[0]["state"]["authenticated_user"], "admin")

    async def test_unconfigured_authentication_blocks_protected_api(self):
        events, called = await self._call_middleware(
            self.http_scope(),
            {"MSF_WEB_USERNAME": "", "MSF_WEB_PASSWORD": ""},
        )
        self.assertFalse(called)
        self.assertEqual(events[0]["status"], 503)
        self.assertIn(b"MSF_WEB_USERNAME", events[1]["body"])

    async def test_origin_is_checked_before_login_is_allowed(self):
        events, called = await self._call_middleware(
            self.http_scope(path="/api/auth/login", headers=[(b"origin", b"https://attacker.example")])
        )
        self.assertFalse(called)
        self.assertEqual(events[0]["status"], 403)

    async def test_websocket_without_session_is_closed(self):
        events = []
        called = []

        async def app(scope, receive, send):
            called.append(scope)

        middleware = AuthenticationMiddleware(app)
        scope = {
            "type": "websocket",
            "path": "/api/console/ws",
            "headers": [(b"origin", b"http://localhost:5173")],
            "client": ("127.0.0.1", 43210),
            "state": {},
        }
        async def send(event):
            events.append(event)

        with patch.dict(os.environ, {
            "MSF_WEB_USERNAME": "admin",
            "MSF_WEB_PASSWORD": "a-long-unique-password",
            "MSF_WEB_CORS_ORIGINS": "http://localhost:5173",
        }):
            await middleware(scope, lambda: None, send)

        self.assertFalse(called)
        self.assertEqual(events[0]["type"], "websocket.close")
        self.assertEqual(events[0]["code"], 4401)


if __name__ == "__main__":
    unittest.main()
