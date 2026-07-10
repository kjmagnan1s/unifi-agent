"""UniFiAgent: the high-level, safety-guarded interface used by the CLI and MCP server.

Design:

* Prefer the official Integration API for reads it covers; use the classic API for depth
  and for everything the Integration API cannot do (radios, speedtest, block/kick, events,
  reports, backups).
* Every mutation is declared in :mod:`operations` with a blast radius and flows through the
  :class:`~unifi_agent.safety.SafetyGuard`. Unconfirmed or dry-run calls return a *preview*
  (``applied: false``) instead of acting, so nothing surprising ever fires.
* Risky mutations (WLAN-group and above) trigger a pre-change backup when configured.
* Radio and WLAN edits re-fetch immediately before writing and send the full object, to
  avoid the last-write-wins race (the API has no revision IDs).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from .api import ClassicClient, IntegrationClient
from .config import Settings, load_settings
from .errors import AuthError, ReadOnlyError, UniFiAgentError
from .models import normalize_client, normalize_device, normalize_health
from .operations import OPERATIONS
from .safety import AuditLog, BlastRadius, SafetyGuard
from .transport import Transport

log = logging.getLogger("unifi_agent.facade")

_BAND_CODES = {
    "2.4ghz": {"ng"}, "2.4": {"ng"}, "ng": {"ng"}, "2g": {"ng"},
    "5ghz": {"na"}, "5": {"na"}, "na": {"na"}, "5g": {"na"},
    "6ghz": {"6e", "ax"}, "6": {"6e", "ax"}, "6e": {"6e", "ax"}, "6g": {"6e", "ax"},
}


def apply_radio_change(
    radio_table: list[dict[str, Any]], band_codes: set[str], changes: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return (new full radio_table, diff). Pure function for testability.

    ``changes`` keys: channel, ht (width), tx_power_mode, tx_power. Only the radios whose
    ``radio`` code is in ``band_codes`` are modified; the rest are passed through unchanged
    (the API requires the complete array).
    """
    new_table: list[dict[str, Any]] = []
    diff: list[dict[str, Any]] = []
    matched = False
    for radio in radio_table:
        entry = dict(radio)
        if radio.get("radio") in band_codes:
            matched = True
            before = {}
            after = {}
            for key, value in changes.items():
                if value is None:
                    continue
                if entry.get(key) != value:
                    before[key] = entry.get(key)
                    after[key] = value
                entry[key] = value
            if after:
                diff.append({"radio": radio.get("radio"), "name": radio.get("name"),
                             "before": before, "after": after})
        new_table.append(entry)
    if not matched:
        raise UniFiAgentError(
            f"No radio matched band(s) {sorted(band_codes)} on this device; "
            f"available: {[r.get('radio') for r in radio_table]}"
        )
    return new_table, diff


class UniFiAgent:
    """Primary entry point. Use as an async context manager."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or load_settings()
        self.transport = Transport(self.settings)
        self.audit = AuditLog(self.settings.audit_dir)
        self.guard = SafetyGuard(
            read_only=self.settings.read_only,
            max_blast_radius=self.settings.max_blast_radius,
            audit=self.audit,
        )
        self._classic: ClassicClient | None = None
        self._integration: IntegrationClient | None = None
        self._site_id: str | None = None

    async def __aenter__(self) -> UniFiAgent:
        await self.transport.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.transport.aclose()

    # -- client accessors ------------------------------------------------------

    @property
    def classic(self) -> ClassicClient:
        if self._classic is None:
            self._classic = ClassicClient(self.settings, self.transport)
        return self._classic

    @property
    def integration(self) -> IntegrationClient:
        if self._integration is None:
            self._integration = IntegrationClient(self.settings, self.transport)
        return self._integration

    def _require_classic(self) -> ClassicClient:
        if not self.settings.has_classic_auth():
            raise AuthError(
                "This operation needs the classic API (local admin login). It is not "
                "available through the Integration API key. Run `unifi-agent setup` to add "
                "a local admin, or use the Integration-API-capable operations."
            )
        return self.classic

    async def capabilities(self) -> dict[str, Any]:
        return {
            "integration_api": self.settings.has_integration_auth(),
            "classic_api": self.settings.has_classic_auth(),
            "read_only": self.settings.read_only,
            "max_blast_radius": self.settings.max_blast_radius.label,
            "backup_before_risky": self.settings.backup_before_risky,
            "host": self.settings.host,
            "site": self.settings.site,
        }

    # -- reads -----------------------------------------------------------------

    async def overview(self) -> dict[str, Any]:
        """A single at-a-glance snapshot of the network."""
        if self.settings.has_classic_auth():
            health_rows, devices, clients = await asyncio.gather(
                self.classic.health(), self.classic.devices(), self.classic.clients()
            )
            devs = [normalize_device(d) for d in devices]
            return {
                "health": normalize_health(health_rows),
                "device_count": len(devs),
                "devices_online": sum(1 for d in devs if d["online"]),
                "client_count": len(clients),
                "clients_wireless": sum(1 for c in clients if not c.get("is_wired")),
                "aps": [d for d in devs if d["type"] == "uap"],
                "gateway": next((d for d in devs if d["type"] in ("ugw", "udm")), None),
            }
        # Integration-only fallback
        site_id = await self._site()
        devices = await self.integration.devices(site_id)
        clients = await self.integration.clients(site_id)
        return {
            "health": {},
            "device_count": len(devices),
            "client_count": len(clients),
            "note": "Limited overview (Integration API only; add a local admin for health).",
        }

    async def list_devices(self) -> list[dict[str, Any]]:
        if self.settings.has_classic_auth():
            return [normalize_device(d) for d in await self.classic.devices()]
        site_id = await self._site()
        return await self.integration.devices(site_id)

    async def list_clients(self) -> list[dict[str, Any]]:
        if self.settings.has_classic_auth():
            return [normalize_client(c) for c in await self.classic.clients()]
        site_id = await self._site()
        return await self.integration.clients(site_id)

    async def health(self) -> dict[str, Any]:
        return normalize_health(await self._require_classic().health())

    async def events(self, limit: int = 50, within_hours: int = 24) -> list[dict[str, Any]]:
        rows = await self._require_classic().events(limit=limit, within_hours=within_hours)
        return [
            {"time": r.get("datetime") or r.get("time"), "key": r.get("key"),
             "msg": r.get("msg"), "subsystem": r.get("subsystem"), "ap": r.get("ap_displayName")}
            for r in rows[:limit]
        ]

    async def alarms(self) -> list[dict[str, Any]]:
        return await self._require_classic().alarms()

    async def speedtest_last(self) -> dict[str, Any]:
        st = await self._require_classic().speedtest_status()
        return {
            "rundate": st.get("rundate"),
            "latency_ms": st.get("latency"),
            "download_mbps": st.get("xput_download"),
            "upload_mbps": st.get("xput_upload"),
            "status_download": st.get("status_download"),
            "status_upload": st.get("status_upload"),
        }

    async def radio_status(self) -> list[dict[str, Any]]:
        """Per-AP radio configuration, for optimization decisions."""
        devices = await self._require_classic().devices()
        out = []
        for d in devices:
            if d.get("type") != "uap":
                continue
            nd = normalize_device(d)
            out.append({"name": nd["name"], "mac": nd["mac"], "online": nd["online"],
                        "clients": nd["clients"], "radios": nd["radios"]})
        return out

    async def _site(self) -> str:
        if self._site_id is None:
            self._site_id = await self.integration.default_site_id()
        return self._site_id

    # -- guarded mutation plumbing ---------------------------------------------

    async def _guarded(
        self,
        op_name: str,
        details: dict[str, Any],
        *,
        confirm: bool,
        dry_run: bool,
        override_blast_radius: bool,
        predict: Any,
        apply: Callable[[], Awaitable[Any]],
    ) -> dict[str, Any]:
        op = OPERATIONS[op_name]
        decision = self.guard.evaluate(
            op, confirm=confirm, dry_run=dry_run,
            override_blast_radius=override_blast_radius, details=details,
        )
        preview = {
            "operation": op_name,
            "blast_radius": decision.blast_radius,
            "disruption": decision.disruption,
            "warnings": decision.warnings,
            "predicted_change": predict,
            "details": details,
        }
        if not decision.allowed:
            return {"applied": False, "reason": decision.reason, **preview}

        # Pre-change snapshot for higher-radius mutations.
        snapshot = None
        if (self.settings.backup_before_risky
                and op.blast_radius >= BlastRadius.WLAN_GROUP
                and self.settings.has_classic_auth()):
            try:
                snapshot = await self.classic.create_backup()
                log.info("Pre-change backup created for %s", op_name)
            except Exception as exc:  # noqa: BLE001
                log.warning("Pre-change backup failed (continuing): %s", exc)

        result = await apply()
        self.audit.record("mutation.result", {"operation": op_name, "details": details})
        return {"applied": True, "reason": "confirmed", "snapshot": bool(snapshot),
                "result": result, **preview}

    # -- mutations -------------------------------------------------------------

    _GATEWAY_TYPES = ("ugw", "udm", "uxg", "ucg")

    async def _find_device(self, identifier: str) -> dict[str, Any] | None:
        """Return the raw device dict matching a MAC or name, or None if not in inventory."""
        devices = await self._require_classic().devices()
        ident = identifier.lower()
        for d in devices:
            if d.get("mac", "").lower() == ident or (d.get("name") or "").lower() == ident:
                return d
        return None

    async def _resolve_ap(self, identifier: str) -> dict[str, Any]:
        device = await self._find_device(identifier)
        if device is None:
            raise UniFiAgentError(f"No device matched {identifier!r}.")
        return device

    async def set_radio(
        self,
        ap: str,
        band: str,
        *,
        channel: int | str | None = None,
        width_mhz: int | None = None,
        tx_power_mode: str | None = None,
        tx_power: int | None = None,
        confirm: bool = False,
        dry_run: bool = False,
        override_blast_radius: bool = False,
    ) -> dict[str, Any]:
        """Set channel / width / TX power for one band on one AP (read-modify-write)."""
        codes = _BAND_CODES.get(band.strip().lower())
        if not codes:
            raise UniFiAgentError(f"Unknown band {band!r}; use 2.4GHz, 5GHz, or 6GHz.")
        # A tx_power value in dBm is only honored when tx_power_mode is "custom"; setting the
        # value without the mode is silently ignored by the controller. Couple them here.
        if tx_power is not None and tx_power_mode is None:
            tx_power_mode = "custom"
        changes = {"channel": channel, "ht": width_mhz,
                   "tx_power_mode": tx_power_mode, "tx_power": tx_power}
        changes = {k: v for k, v in changes.items() if v is not None}
        if not changes:
            raise UniFiAgentError("Nothing to change; specify channel/width/tx_power.")

        device = await self._resolve_ap(ap)
        _, diff = apply_radio_change(device.get("radio_table", []), codes, changes)
        details = {"ap": device.get("name"), "mac": device.get("mac"), "band": band}

        async def _apply() -> Any:
            # Re-fetch immediately before writing to minimize the last-write-wins window.
            fresh = await self.classic.device(device["mac"])
            new_table, _ = apply_radio_change(fresh.get("radio_table", []), codes, changes)
            return await self.classic.put_device(fresh["_id"], {"radio_table": new_table})

        return await self._guarded(
            "set_radio", details, confirm=confirm, dry_run=dry_run,
            override_blast_radius=override_blast_radius, predict=diff, apply=_apply,
        )

    async def restart_device(
        self, mac: str, *, confirm: bool = False, dry_run: bool = False,
        override_blast_radius: bool = False,
    ) -> dict[str, Any]:
        device = await self._find_device(mac)
        target = device["mac"] if device else mac
        # Rebooting the gateway takes the whole network (and this session) down, so it must
        # be classified GATEWAY — not DEVICE — to trip the ceiling and the self-lockout warning.
        is_gateway = bool(device and device.get("type") in self._GATEWAY_TYPES)
        op = "restart_gateway" if is_gateway else "restart_device"
        return await self._guarded(
            op, {"mac": target, "gateway": is_gateway}, confirm=confirm, dry_run=dry_run,
            override_blast_radius=override_blast_radius,
            predict={"action": "reboot", "mac": target},
            apply=lambda: self._require_classic().restart_device(target),
        )

    async def run_speedtest(
        self, *, confirm: bool = False, dry_run: bool = False,
        override_blast_radius: bool = False, wait: bool = True, timeout_s: int = 60,
    ) -> dict[str, Any]:
        async def _apply() -> Any:
            # speedtest-status always reports the LAST run's throughput, so we must wait for
            # a *new* result: capture the current rundate, then poll until it changes.
            baseline = await self._require_classic().speedtest_status()
            prev_rundate = baseline.get("rundate")
            await self.classic.speedtest()
            if not wait:
                return {"started": True, "prev_rundate": prev_rundate}
            for _ in range(max(1, timeout_s // 3)):
                await asyncio.sleep(3)
                st = await self.classic.speedtest_status()
                rundate = st.get("rundate")
                is_new = rundate is not None and rundate != prev_rundate
                if is_new and st.get("xput_download") is not None:
                    return {"download_mbps": st.get("xput_download"),
                            "upload_mbps": st.get("xput_upload"),
                            "latency_ms": st.get("latency"), "rundate": rundate}
            return {"started": True, "note": "did not complete within timeout"}

        return await self._guarded(
            "run_speedtest", {}, confirm=confirm, dry_run=dry_run,
            override_blast_radius=override_blast_radius,
            predict={"action": "run ISP speedtest"}, apply=_apply,
        )

    async def block_client(
        self, mac: str, *, confirm: bool = False, dry_run: bool = False,
        override_blast_radius: bool = False,
    ) -> dict[str, Any]:
        return await self._guarded(
            "block_client", {"mac": mac}, confirm=confirm, dry_run=dry_run,
            override_blast_radius=override_blast_radius,
            predict={"action": "block", "mac": mac},
            apply=lambda: self._require_classic().block_client(mac),
        )

    async def unblock_client(
        self, mac: str, *, confirm: bool = False, dry_run: bool = False,
        override_blast_radius: bool = False,
    ) -> dict[str, Any]:
        return await self._guarded(
            "unblock_client", {"mac": mac}, confirm=confirm, dry_run=dry_run,
            override_blast_radius=override_blast_radius,
            predict={"action": "unblock", "mac": mac},
            apply=lambda: self._require_classic().unblock_client(mac),
        )

    async def kick_client(
        self, mac: str, *, confirm: bool = False, dry_run: bool = False,
        override_blast_radius: bool = False,
    ) -> dict[str, Any]:
        return await self._guarded(
            "kick_client", {"mac": mac}, confirm=confirm, dry_run=dry_run,
            override_blast_radius=override_blast_radius,
            predict={"action": "kick", "mac": mac},
            apply=lambda: self._require_classic().kick_client(mac),
        )

    async def set_locate(
        self, mac: str, on: bool = True, *, confirm: bool = False, dry_run: bool = False,
    ) -> dict[str, Any]:
        return await self._guarded(
            "set_locate", {"mac": mac, "on": on}, confirm=confirm, dry_run=dry_run,
            override_blast_radius=False,
            predict={"action": "locate LED", "on": on, "mac": mac},
            apply=lambda: self._require_classic().locate_device(mac, on),
        )

    async def toggle_wlan(
        self, wlan_id: str, enabled: bool, *, confirm: bool = False, dry_run: bool = False,
        override_blast_radius: bool = False,
    ) -> dict[str, Any]:
        async def _apply() -> Any:
            wlans = await self.classic.wlanconf()
            match = next((w for w in wlans if w.get("_id") == wlan_id
                          or w.get("name") == wlan_id), None)
            if not match:
                raise UniFiAgentError(f"No WLAN matched {wlan_id!r}.")
            payload = dict(match)
            payload["enabled"] = enabled
            return await self.classic.put_wlanconf(match["_id"], payload)

        return await self._guarded(
            "toggle_wlan", {"wlan": wlan_id, "enabled": enabled}, confirm=confirm,
            dry_run=dry_run, override_blast_radius=override_blast_radius,
            predict={"action": "enable" if enabled else "disable", "wlan": wlan_id},
            apply=_apply,
        )

    async def power_cycle_port(
        self, switch: str, port_idx: int, *, confirm: bool = False, dry_run: bool = False,
        override_blast_radius: bool = False,
    ) -> dict[str, Any]:
        device = await self._resolve_ap(switch)
        target = device["mac"]
        return await self._guarded(
            "power_cycle_port", {"switch": target, "port_idx": port_idx}, confirm=confirm,
            dry_run=dry_run, override_blast_radius=override_blast_radius,
            predict={"action": "power-cycle PoE port", "switch": target, "port_idx": port_idx},
            apply=lambda: self._require_classic().power_cycle_port(target, port_idx),
        )

    async def authorize_guest(
        self, mac: str, *, minutes: int = 60, up_kbps: int | None = None,
        down_kbps: int | None = None, quota_mb: int | None = None,
        confirm: bool = False, dry_run: bool = False, override_blast_radius: bool = False,
    ) -> dict[str, Any]:
        return await self._guarded(
            "authorize_guest",
            {"mac": mac, "minutes": minutes}, confirm=confirm, dry_run=dry_run,
            override_blast_radius=override_blast_radius,
            predict={"action": "authorize guest", "mac": mac, "minutes": minutes},
            apply=lambda: self._require_classic().authorize_guest(
                mac, minutes=minutes, up_kbps=up_kbps, down_kbps=down_kbps, quota_mb=quota_mb),
        )

    async def unauthorize_guest(
        self, mac: str, *, confirm: bool = False, dry_run: bool = False,
        override_blast_radius: bool = False,
    ) -> dict[str, Any]:
        return await self._guarded(
            "unauthorize_guest", {"mac": mac}, confirm=confirm, dry_run=dry_run,
            override_blast_radius=override_blast_radius,
            predict={"action": "unauthorize guest", "mac": mac},
            apply=lambda: self._require_classic().unauthorize_guest(mac),
        )

    async def create_backup(self, days: int = -1) -> dict[str, Any]:
        """Create a config backup. Blast radius is none, but it is still a write, so it
        respects read-only mode (the documented "no mutation is ever sent" contract)."""
        if self.settings.read_only:
            self.audit.record("mutation.refused",
                              {"operation": "create_backup", "reason": "read_only"})
            raise ReadOnlyError(
                "create_backup is a write; the agent is read-only (UNIFI_READ_ONLY=true)."
            )
        result = await self._require_classic().create_backup(days=days)
        self.audit.record("mutation.result", {"operation": "create_backup"})
        return {"applied": True, "operation": "create_backup", "result": result}
