"""Authentication for both UniFi API surfaces.

Two independent mechanisms, matching the two APIs:

* :class:`ApiKeyAuth` — stateless ``X-API-KEY`` header for the official Integration API.
* :class:`SessionAuth` — cookie + CSRF token for the classic controller API. Logs in
  once, reuses the ``TOKEN`` cookie until it expires or a request comes back
  ``LoginRequired``, and tracks CSRF-token rotation. It deliberately never logs in per
  request: UniFi OS rate-limits ``/api/auth/login`` and locks out on frequency alone.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import logging
import time

import httpx

from .errors import AuthError, UniFiAPIError
from .transport import Transport

log = logging.getLogger("unifi_agent.auth")


class ApiKeyAuth:
    """Header provider for the Integration API. Stateless."""

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    def headers(self) -> dict[str, str]:
        return {"X-API-KEY": self._api_key, "Accept": "application/json"}


def _decode_csrf_from_jwt(token: str) -> str | None:
    """Extract the ``csrfToken`` claim from the TOKEN JWT (fallback when no header)."""
    parts = token.split(".")
    if len(parts) < 2:
        return None
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)  # pad base64url
    try:
        data = json.loads(base64.urlsafe_b64decode(payload))
    except (binascii.Error, json.JSONDecodeError, ValueError):
        return None
    return data.get("csrfToken")


class SessionAuth:
    """Cookie + CSRF session for the classic API.

    Thread-safety: guarded by an asyncio lock so concurrent callers trigger at most one
    login. Call :meth:`headers` before each mutating request to get the current CSRF
    token, and feed every response back through :meth:`update_from_response` so rotated
    tokens are captured.
    """

    def __init__(self, transport: Transport, username: str, password: str) -> None:
        self._transport = transport
        self._username = username
        self._password = password
        self._csrf: str | None = None
        self._expires_at: float = 0.0
        self._logged_in = False
        self._lock = asyncio.Lock()

    @property
    def logged_in(self) -> bool:
        return self._logged_in and time.time() < self._expires_at

    async def ensure_login(self, *, force: bool = False) -> None:
        async with self._lock:
            if self.logged_in and not force:
                return
            await self._login()

    async def _login(self) -> None:
        body = {"username": self._username, "password": self._password, "remember": True}
        resp = await self._transport.request(
            "POST", "/api/auth/login", json=body, headers={"Accept": "application/json"}
        )
        if resp.status_code == 499 or _msg(resp) == "api.err.Ubic2faTokenRequired":
            raise AuthError(
                "This account requires 2FA. Use a dedicated service admin without 2FA, "
                "or an API key, for non-interactive access."
            )
        if resp.status_code == 401:
            raise AuthError(
                "Login rejected (401). The classic API needs a LOCAL admin account; "
                "cloud/SSO-only accounts are rejected. Create a local-only admin and store "
                "it with `unifi-agent setup`."
            )
        if resp.status_code >= 400:
            raise AuthError(f"Login failed: HTTP {resp.status_code} {_msg(resp) or ''}".strip())

        self._capture(resp)
        self._logged_in = True
        # UniFi does not always advertise the cookie lifetime; default to a conservative
        # window and rely on LoginRequired-triggered re-login as the real backstop.
        log.info("Classic API session established for %s", self._username)

    def _capture(self, resp: httpx.Response) -> None:
        csrf = resp.headers.get("x-csrf-token") or resp.headers.get("x-updated-csrf-token")
        if not csrf:
            token = resp.cookies.get("TOKEN") or self._transport.client.cookies.get("TOKEN")
            if token:
                csrf = _decode_csrf_from_jwt(token)
        if csrf:
            self._csrf = csrf
        expire_hdr = resp.headers.get("x-token-expire-time")
        if expire_hdr:
            try:
                # Some builds send an absolute epoch (ms), others a relative seconds value.
                val = float(expire_hdr)
                self._expires_at = val / 1000.0 if val > 1e12 else time.time() + val
            except ValueError:
                self._expires_at = time.time() + 3600
        else:
            self._expires_at = time.time() + 3600

    def update_from_response(self, resp: httpx.Response) -> None:
        """Capture a rotated CSRF token from any response."""
        rotated = resp.headers.get("x-updated-csrf-token") or resp.headers.get("x-csrf-token")
        if rotated:
            self._csrf = rotated

    def headers(self, *, mutating: bool) -> dict[str, str]:
        h = {"Accept": "application/json"}
        if mutating:
            if not self._csrf:
                raise AuthError("No CSRF token available; call ensure_login() first.")
            h["X-CSRF-Token"] = self._csrf
        return h


def _msg(resp: httpx.Response) -> str | None:
    try:
        data = resp.json()
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(data, dict):
        meta = data.get("meta")
        if isinstance(meta, dict):
            return meta.get("msg")
        return data.get("code") or data.get("message")
    return None


def is_login_required(resp: httpx.Response) -> bool:
    """True if the response indicates the classic session went stale."""
    if resp.status_code != 401:
        return False
    return _msg(resp) in {"api.err.LoginRequired", None}


def raise_for_meta(resp: httpx.Response, path: str) -> None:
    """Raise :class:`UniFiAPIError` if a classic-API response signals an error."""
    try:
        data = resp.json()
    except (json.JSONDecodeError, ValueError) as exc:
        if resp.status_code >= 400:
            raise UniFiAPIError(resp.text[:200] or "request failed",
                                status=resp.status_code, path=path) from exc
        return
    if isinstance(data, dict):
        meta = data.get("meta")
        if isinstance(meta, dict) and meta.get("rc") == "error":
            raise UniFiAPIError(meta.get("msg") or "error", status=resp.status_code,
                                code=meta.get("msg"), path=path)
        # Integration-API error envelope
        if resp.status_code >= 400 and ("code" in data or "message" in data):
            raise UniFiAPIError(
                data.get("message") or "error",
                status=resp.status_code,
                code=data.get("code"),
                path=path,
            )
    if resp.status_code >= 400:
        raise UniFiAPIError(f"HTTP {resp.status_code}", status=resp.status_code, path=path)
