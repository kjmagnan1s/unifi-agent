"""HTTP transport with TLS certificate pinning for self-signed UniFi consoles.

UniFi consoles serve a self-signed certificate whose CN (``unifi.local``) does not match
the LAN IP you connect to. Blanket ``verify=False`` is the usual "fix" and it throws away
all MITM protection. Instead we pin:

* On first connect (``pin`` mode) we fetch the console's certificate and store it at
  ``pinned-cert.pem``. Thereafter that certificate is the *only* trusted root, so any
  other certificate — including a real MITM — fails validation. Hostname matching is
  disabled (we connect by IP), but identity is still enforced by the pin.
* ``system`` mode uses normal CA verification, for consoles that have a real hostname and
  a CA-issued certificate.
* ``insecure`` mode disables verification entirely and is meant only for throwaway tests;
  it is loud in logs.

The transport also centralizes retries with exponential backoff and honors ``Retry-After``
on HTTP 429, because UniFi OS locks out clients that hammer it.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import socket
import ssl
import sys

import httpx

from .config import Settings
from .errors import RateLimitError, TLSPinError, UniFiAgentError

log = logging.getLogger("unifi_agent.transport")

# Methods that are safe to retry automatically on transient network errors.
_IDEMPOTENT = {"GET", "HEAD", "OPTIONS"}


def fetch_peer_certificate(host: str, port: int = 443, timeout: float = 10.0) -> str:
    """Return the PEM of the certificate ``host:port`` presents. No verification."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with (
        socket.create_connection((host, port), timeout=timeout) as sock,
        ctx.wrap_socket(sock, server_hostname=host) as ssock,
    ):
        der = ssock.getpeercert(binary_form=True)
    if not der:
        raise TLSPinError(f"{host}:{port} presented no certificate")
    return ssl.DER_cert_to_PEM_cert(der)


def certificate_fingerprint(pem: str) -> str:
    """SHA-256 fingerprint of a PEM cert, formatted like OpenSSL (colon-separated hex)."""
    der = ssl.PEM_cert_to_DER_cert(pem)
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def _host_and_port(base_url: str) -> tuple[str, int]:
    parsed = httpx.URL(base_url)
    return parsed.host, parsed.port or 443


def pin_certificate(settings: Settings, *, repin: bool = False) -> str:
    """Fetch and store the console certificate. Returns its fingerprint.

    Raises :class:`TLSPinError` if a different certificate is already pinned and
    ``repin`` is False.
    """
    host, port = _host_and_port(settings.base_url)
    pem = fetch_peer_certificate(host, port, timeout=settings.request_timeout)
    fingerprint = certificate_fingerprint(pem)
    path = settings.pinned_cert_path

    if path.is_file() and not repin:
        existing_fp = certificate_fingerprint(path.read_text())
        if existing_fp != fingerprint:
            raise TLSPinError(
                f"Certificate for {host} changed.\n"
                f"  pinned: {existing_fp}\n"
                f"  seen:   {fingerprint}\n"
                "If you updated firmware or installed a custom certificate, re-pin with "
                "`unifi-agent trust --repin` after confirming the fingerprint in the "
                "console UI. Otherwise this may be an interception attempt."
            )
        return existing_fp

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(pem)
    path.chmod(0o600)
    log.info("Pinned certificate for %s (%s)", host, fingerprint)
    return fingerprint


def _build_ssl_context(settings: Settings) -> ssl.SSLContext | bool:
    """Return the ``verify`` argument for httpx based on the TLS mode."""
    mode = settings.tls_mode
    if mode == "insecure":
        log.warning("TLS verification DISABLED (UNIFI_TLS=insecure). MITM is possible.")
        return False
    if mode == "system":
        return True  # httpx uses the default CA bundle + hostname checking
    # pin mode
    path = settings.pinned_cert_path
    if not path.is_file():
        # Trust on first use. Surface the fingerprint LOUDLY on stderr (the logger is
        # usually quiet in CLI/MCP runs) so a first-contact MITM can't be pinned unnoticed;
        # the user should verify it against the console UI or run `unifi-agent trust` first.
        fingerprint = pin_certificate(settings)
        host, _ = _host_and_port(settings.base_url)
        print(
            f"[unifi-agent] Pinned {host} on first use (trust-on-first-use):\n"
            f"    SHA-256 {fingerprint}\n"
            f"    Verify this in the console UI (Settings -> Control Plane -> Console). "
            f"Re-pin after firmware/cert changes with `unifi-agent trust --repin`.",
            file=sys.stderr,
        )
    ctx = ssl.create_default_context(cafile=str(path))
    # We connect by IP; the cert CN is unifi.local. Identity is enforced by the pin
    # (this cert is the only trusted root), so hostname matching is intentionally off.
    ctx.check_hostname = False
    return ctx


class Transport:
    """Owns a single pooled, TLS-pinned :class:`httpx.AsyncClient`."""

    def __init__(self, settings: Settings, *, max_retries: int = 3) -> None:
        self.settings = settings
        self.max_retries = max_retries
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> Transport:
        await self.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def start(self) -> None:
        if self._client is not None:
            return
        verify = _build_ssl_context(self.settings)
        self._client = httpx.AsyncClient(
            base_url=self.settings.base_url,
            verify=verify,
            timeout=httpx.Timeout(self.settings.request_timeout),
            follow_redirects=False,
            headers={"User-Agent": "unifi-agent/0.1 (+https://github.com/kjmagnan1s)"},
        )

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise UniFiAgentError("Transport not started; use `async with` or call start().")
        return self._client

    async def request(self, method: str, url: str, **kwargs: object) -> httpx.Response:
        """Issue a request with retry/backoff. Raises :class:`RateLimitError` on 429."""
        attempt = 0
        while True:
            attempt += 1
            try:
                resp = await self.client.request(method, url, **kwargs)  # type: ignore[arg-type]
            except (httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError) as exc:
                if method.upper() in _IDEMPOTENT and attempt <= self.max_retries:
                    await asyncio.sleep(min(2 ** (attempt - 1), 8))
                    continue
                raise UniFiAgentError(f"{method} {url} failed: {exc}") from exc

            if resp.status_code == 429:
                retry_after = _parse_retry_after(resp)
                if attempt <= self.max_retries:
                    await asyncio.sleep(retry_after or min(2 ** attempt, 30))
                    continue
                raise RateLimitError(
                    "Rate limited by the console (HTTP 429). Backing off did not clear it.",
                    retry_after=retry_after,
                    status=429,
                    path=url,
                )
            return resp


def _parse_retry_after(resp: httpx.Response) -> float | None:
    value = resp.headers.get("Retry-After")
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None
