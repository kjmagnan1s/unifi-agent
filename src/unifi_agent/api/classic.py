"""Classic UniFi controller API client (cookie + CSRF).

Base path on a UniFi OS console: ``/proxy/network/api/s/<site>/``. This is the internal
API the web UI itself drives. It is unofficial but stable, and it is the *only* surface
for radio tuning, client block/kick, speedtest, events, historical reports, and backups.

Every response envelope is ``{"meta": {"rc": "ok"|"error", ...}, "data": [...]}``. On a
stale session (HTTP 401 ``LoginRequired``) the client re-authenticates once and replays.
"""

from __future__ import annotations

import logging
from typing import Any

from ..auth import SessionAuth, is_login_required, raise_for_meta
from ..config import Settings
from ..errors import AuthError, UniFiAPIError
from ..transport import Transport

log = logging.getLogger("unifi_agent.classic")


class ClassicClient:
    def __init__(self, settings: Settings, transport: Transport) -> None:
        if not settings.has_classic_auth():
            raise AuthError(
                "Classic API needs a local admin login (UNIFI_USERNAME/UNIFI_PASSWORD). "
                "Run `unifi-agent setup`."
            )
        self.settings = settings
        self.transport = transport
        self.session = SessionAuth(transport, settings.username, settings.password)  # type: ignore[arg-type]

    @property
    def _base(self) -> str:
        return f"/proxy/network/api/s/{self.settings.site}"

    async def _request(
        self, method: str, path: str, *, json: Any = None, mutating: bool = False,
        timeout: float | None = None,
    ) -> list[dict[str, Any]]:
        await self.session.ensure_login()
        url = f"{self._base}{path}"
        headers = self.session.headers(mutating=mutating)
        kw: dict[str, Any] = {"json": json, "headers": headers}
        if timeout is not None:
            kw["timeout"] = timeout
        resp = await self.transport.request(method, url, **kw)

        if is_login_required(resp):
            log.info("Classic session stale; re-authenticating")
            await self.session.ensure_login(force=True)
            kw["headers"] = self.session.headers(mutating=mutating)
            resp = await self.transport.request(method, url, **kw)

        self.session.update_from_response(resp)
        raise_for_meta(resp, url)
        data = resp.json()
        return data.get("data", []) if isinstance(data, dict) else []

    # -- generic verbs (exposed for advanced/uncovered endpoints) --------------

    async def get(self, path: str) -> list[dict[str, Any]]:
        return await self._request("GET", path)

    async def post(
        self, path: str, body: dict[str, Any], *, timeout: float | None = None
    ) -> list[dict[str, Any]]:
        return await self._request("POST", path, json=body, mutating=True, timeout=timeout)

    async def put(self, path: str, body: dict[str, Any]) -> list[dict[str, Any]]:
        return await self._request("PUT", path, json=body, mutating=True)

    async def delete(self, path: str) -> list[dict[str, Any]]:
        return await self._request("DELETE", path, mutating=True)

    # -- reads -----------------------------------------------------------------

    async def health(self) -> list[dict[str, Any]]:
        return await self.get("/stat/health")

    async def sysinfo(self) -> dict[str, Any]:
        rows = await self.get("/stat/sysinfo")
        return rows[0] if rows else {}

    async def devices(self) -> list[dict[str, Any]]:
        return await self.get("/stat/device")

    async def device(self, mac: str) -> dict[str, Any]:
        rows = await self.get(f"/stat/device/{mac.lower()}")
        return rows[0] if rows else {}

    async def clients(self) -> list[dict[str, Any]]:
        return await self.get("/stat/sta")

    async def all_clients(self) -> list[dict[str, Any]]:
        return await self.get("/stat/alluser")

    async def known_clients(self) -> list[dict[str, Any]]:
        return await self.get("/rest/user")

    async def gateway(self) -> dict[str, Any]:
        rows = await self.get("/stat/gateway")
        return rows[0] if rows else {}

    async def events(self, limit: int = 100, within_hours: int = 24) -> list[dict[str, Any]]:
        """Events, newest first.

        Some UniFi OS builds (e.g. Network 10.4.x) no longer expose ``/stat/event`` and
        return 404. We surface that as an empty list, but any *other* error (auth, network)
        propagates so failures aren't silently masked as "no events".
        """
        path = f"/stat/event?_limit={limit}&_sort=-time&within={within_hours}"
        try:
            return await self.get(path)
        except UniFiAPIError as exc:
            if exc.status == 404:
                log.info("events endpoint unavailable on this build (404); returning empty")
                return []
            raise

    async def alarms(self, archived: bool = False) -> list[dict[str, Any]]:
        """Alarms. Prefers ``/stat/alarm``; on 404 falls back to ``/list/alarm`` (used by
        newer builds). Non-404 errors propagate."""
        try:
            return await self.get(f"/stat/alarm?archived={str(archived).lower()}")
        except UniFiAPIError as exc:
            if exc.status == 404:
                return await self.get("/list/alarm")
            raise

    async def rogue_aps(self, within_hours: int = 24) -> list[dict[str, Any]]:
        return await self.post("/stat/rogueap", {"within": within_hours})

    async def dpi(self) -> list[dict[str, Any]]:
        return await self.get("/stat/sitedpi")

    async def report(
        self,
        interval: str,
        scope: str,
        *,
        attrs: list[str],
        start_ms: int,
        end_ms: int,
        macs: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Historical report. ``interval`` in {5minutes,hourly,daily,monthly};
        ``scope`` in {site,user,ap,gw,sw}. Timestamps are epoch **milliseconds**."""
        body: dict[str, Any] = {"attrs": attrs, "start": start_ms, "end": end_ms}
        if macs:
            body["macs"] = macs
        return await self.post(f"/stat/report/{interval}.{scope}", body)

    async def wlanconf(self) -> list[dict[str, Any]]:
        return await self.get("/rest/wlanconf")

    async def networkconf(self) -> list[dict[str, Any]]:
        return await self.get("/rest/networkconf")

    async def port_forwards(self) -> list[dict[str, Any]]:
        return await self.get("/rest/portforward")

    async def firewall_rules(self) -> list[dict[str, Any]]:
        return await self.get("/rest/firewallrule")

    # -- device / radio writes -------------------------------------------------

    async def put_device(self, device_id: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
        """Update a device object (e.g. full ``radio_table``) by its Mongo ``_id``."""
        return await self.put(f"/rest/device/{device_id}", payload)

    async def devmgr(self, cmd: str, **kwargs: Any) -> list[dict[str, Any]]:
        return await self.post("/cmd/devmgr", {"cmd": cmd, **kwargs})

    async def restart_device(self, mac: str, *, soft: bool = True) -> list[dict[str, Any]]:
        return await self.devmgr("restart", mac=mac.lower(),
                                 reboot_type="soft" if soft else "hard")

    async def power_cycle_port(self, mac: str, port_idx: int) -> list[dict[str, Any]]:
        return await self.devmgr("power-cycle", mac=mac.lower(), port_idx=port_idx)

    async def locate_device(self, mac: str, on: bool = True) -> list[dict[str, Any]]:
        return await self.devmgr("set-locate" if on else "unset-locate", mac=mac.lower())

    async def force_provision(self, mac: str) -> list[dict[str, Any]]:
        return await self.devmgr("force-provision", mac=mac.lower())

    async def speedtest(self) -> list[dict[str, Any]]:
        return await self.devmgr("speedtest")

    async def speedtest_status(self) -> dict[str, Any]:
        rows = await self.devmgr("speedtest-status")
        return rows[0] if rows else {}

    # -- client writes ---------------------------------------------------------

    async def stamgr(self, cmd: str, **kwargs: Any) -> list[dict[str, Any]]:
        return await self.post("/cmd/stamgr", {"cmd": cmd, **kwargs})

    async def block_client(self, mac: str) -> list[dict[str, Any]]:
        return await self.stamgr("block-sta", mac=mac.lower())

    async def unblock_client(self, mac: str) -> list[dict[str, Any]]:
        return await self.stamgr("unblock-sta", mac=mac.lower())

    async def kick_client(self, mac: str) -> list[dict[str, Any]]:
        return await self.stamgr("kick-sta", mac=mac.lower())

    async def authorize_guest(
        self, mac: str, *, minutes: int = 60, up_kbps: int | None = None,
        down_kbps: int | None = None, quota_mb: int | None = None,
    ) -> list[dict[str, Any]]:
        body: dict[str, Any] = {"cmd": "authorize-guest", "mac": mac.lower(), "minutes": minutes}
        if up_kbps:
            body["up"] = up_kbps
        if down_kbps:
            body["down"] = down_kbps
        if quota_mb:
            body["bytes"] = quota_mb
        return await self.post("/cmd/stamgr", body)

    async def unauthorize_guest(self, mac: str) -> list[dict[str, Any]]:
        return await self.stamgr("unauthorize-guest", mac=mac.lower())

    # -- WLAN writes -----------------------------------------------------------

    async def put_wlanconf(self, wlan_id: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
        return await self.put(f"/rest/wlanconf/{wlan_id}", payload)

    # -- backups ---------------------------------------------------------------

    async def list_backups(self) -> list[dict[str, Any]]:
        return await self.post("/cmd/backup", {"cmd": "list-backups"})

    async def create_backup(self, days: int = 0) -> list[dict[str, Any]]:
        """Trigger a backup. ``days=0`` = config only (fast; the sensible restore point);
        ``days=-1`` = include all historical stats (large and slow). Uses a longer timeout
        because the console can take well over the default 30s to build the archive."""
        return await self.post("/cmd/backup", {"cmd": "backup", "days": str(days)}, timeout=180)

    async def delete_backup(self, filename: str) -> list[dict[str, Any]]:
        return await self.post("/cmd/backup", {"cmd": "delete-backup", "filename": filename})

    async def download_backup(self, filename: str) -> bytes:
        """Download a ``.unf`` by filename (or a full server path).

        On a UniFi OS console the Network app is proxied under ``/proxy/network``; the
        download lives at ``/proxy/network/dl/{backup|autobackup}/<filename>`` (autobackups
        use the ``autobackup`` subpath). A bare ``/dl/...`` hits the UniFi OS root and 404s.
        """
        await self.session.ensure_login()
        if filename.startswith("/proxy/network"):
            url = filename
        elif filename.startswith("/"):
            # API returns download paths relative to the Network app (e.g. /dl/backup/x.unf).
            url = f"/proxy/network{filename}"
        else:
            sub = "autobackup" if filename.startswith("autobackup") else "backup"
            url = f"/proxy/network/dl/{sub}/{filename}"
        resp = await self.transport.request("GET", url,
                                            headers=self.session.headers(mutating=False))
        resp.raise_for_status()
        return resp.content
