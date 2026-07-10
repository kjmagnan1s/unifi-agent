"""Official UniFi Network Integration API client (X-API-KEY).

Base path: ``/proxy/network/integration/v1/``. Stateless: every request carries the API
key header, no cookie, no CSRF. Objects are UUID-keyed. Coverage is version-gated — the
full surface (networks, WLANs, firewall CRUD) requires Network 10.x. Use :meth:`info` to
detect the running version at runtime.

Reference: https://developer.ui.com/network/ (versioned OpenAPI specs).
"""

from __future__ import annotations

import logging
from typing import Any

from ..auth import ApiKeyAuth, raise_for_meta
from ..config import Settings
from ..errors import AuthError
from ..transport import Transport

log = logging.getLogger("unifi_agent.integration")

_PREFIX = "/proxy/network/integration/v1"
_PAGE_MAX = 200


class IntegrationClient:
    def __init__(self, settings: Settings, transport: Transport) -> None:
        if not settings.has_integration_auth():
            raise AuthError("Integration API needs UNIFI_API_KEY. Run `unifi-agent setup`.")
        self.settings = settings
        self.transport = transport
        self.auth = ApiKeyAuth(settings.api_key)  # type: ignore[arg-type]

    async def _request(self, method: str, path: str, *, json: Any = None,
                       params: dict[str, Any] | None = None) -> Any:
        url = f"{_PREFIX}{path}"
        resp = await self.transport.request(
            method, url, json=json, params=params, headers=self.auth.headers()
        )
        raise_for_meta(resp, url)
        if resp.status_code == 204 or not resp.content:
            return {}
        return resp.json()

    async def _paginate(self, path: str, *, params: dict[str, Any] | None = None) -> list[dict]:
        """Follow offset/limit pagination and return the concatenated ``data`` list."""
        params = dict(params or {})
        params.setdefault("limit", _PAGE_MAX)
        offset = 0
        items: list[dict] = []
        while True:
            params["offset"] = offset
            body = await self._request("GET", path, params=params)
            page = body.get("data", body) if isinstance(body, dict) else body
            if not isinstance(page, list):
                return items
            items.extend(page)
            count = body.get("count", len(page)) if isinstance(body, dict) else len(page)
            total = body.get("totalCount") if isinstance(body, dict) else None
            offset += len(page)
            if not page or (total is not None and offset >= total) or len(page) < params["limit"]:
                break
            if count == 0:
                break
        return items

    # -- meta ------------------------------------------------------------------

    async def info(self) -> dict[str, Any]:
        """Application version + capabilities. Use to gate version-specific endpoints."""
        return await self._request("GET", "/info")

    async def sites(self) -> list[dict[str, Any]]:
        return await self._paginate("/sites")

    async def default_site_id(self) -> str:
        sites = await self.sites()
        if not sites:
            raise AuthError("Integration API returned no sites for this key.")
        # Prefer the site whose internal name is the configured one.
        for s in sites:
            if s.get("name") == self.settings.site or s.get("internalReference") == self.settings.site:
                return s["id"]
        return sites[0]["id"]

    # -- devices ---------------------------------------------------------------

    async def devices(self, site_id: str) -> list[dict[str, Any]]:
        return await self._paginate(f"/sites/{site_id}/devices")

    async def device(self, site_id: str, device_id: str) -> dict[str, Any]:
        return await self._request("GET", f"/sites/{site_id}/devices/{device_id}")

    async def device_stats(
        self, site_id: str, device_id: str | None = None
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Latest device statistics.

        With ``device_id`` -> the per-device snapshot
        (``/devices/{deviceId}/statistics/latest``, returns one object). Without it -> the
        site-wide collection endpoint (returns a list); availability of the collection form
        is version-dependent.
        """
        if device_id:
            return await self._request(
                "GET", f"/sites/{site_id}/devices/{device_id}/statistics/latest"
            )
        body = await self._request("GET", f"/sites/{site_id}/devices/statistics/latest")
        return body.get("data", []) if isinstance(body, dict) else body

    async def device_action(self, site_id: str, device_id: str, action: str) -> Any:
        return await self._request(
            "POST", f"/sites/{site_id}/devices/{device_id}/actions", json={"action": action}
        )

    async def port_action(self, site_id: str, device_id: str, port_idx: int, action: str) -> Any:
        return await self._request(
            "POST",
            f"/sites/{site_id}/devices/{device_id}/interfaces/ports/{port_idx}/actions",
            json={"action": action},
        )

    # -- clients ---------------------------------------------------------------

    async def clients(self, site_id: str) -> list[dict[str, Any]]:
        return await self._paginate(f"/sites/{site_id}/clients")

    async def client_action(self, site_id: str, client_id: str, action: str,
                            **kwargs: Any) -> Any:
        payload = {"action": action, **kwargs}
        return await self._request(
            "POST", f"/sites/{site_id}/clients/{client_id}/actions", json=payload
        )

    # -- config surfaces (10.x) ------------------------------------------------

    async def networks(self, site_id: str) -> list[dict[str, Any]]:
        return await self._paginate(f"/sites/{site_id}/networks")

    async def wifi_broadcasts(self, site_id: str) -> list[dict[str, Any]]:
        return await self._paginate(f"/sites/{site_id}/wifi/broadcasts")

    async def update_wifi_broadcast(self, site_id: str, broadcast_id: str,
                                    payload: dict[str, Any]) -> Any:
        return await self._request(
            "PUT", f"/sites/{site_id}/wifi/broadcasts/{broadcast_id}", json=payload
        )

    async def firewall_policies(self, site_id: str) -> list[dict[str, Any]]:
        return await self._paginate(f"/sites/{site_id}/firewall/policies")
