"""Unattended diagnostic loops and a WiFi optimization analyzer.

These are read-only by default. :func:`diagnostics_once` collects a health snapshot and
derives findings + optimization recommendations; :func:`monitor` runs it on an interval and
emits JSONL so a cron job, a launchd agent, or an LLM loop can consume it. Recommendations
are *suggestions* — applying them still goes through the guarded mutation path.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from typing import Any

from .facade import UniFiAgent

log = logging.getLogger("unifi_agent.loops")

# 2.4GHz non-overlapping channels (US); 5GHz UNII channels commonly used by UniFi.
_CLEAN_24 = {1, 6, 11}


async def diagnostics_once(agent: UniFiAgent) -> dict[str, Any]:
    """Run one diagnostic pass. Returns a structured report with findings + recommendations."""
    report: dict[str, Any] = {
        "ts": datetime.now(UTC).isoformat(),
        "findings": [],
        "recommendations": [],
    }
    findings: list[dict[str, Any]] = report["findings"]
    recs: list[dict[str, Any]] = report["recommendations"]

    overview = await agent.overview()
    report["overview"] = overview

    health = overview.get("health", {})
    for sub, entry in health.items():
        if entry.get("status") not in (None, "ok"):
            findings.append({"severity": "warning", "area": sub,
                             "detail": f"{sub} subsystem status is '{entry.get('status')}'"})

    # Offline devices.
    devices = await agent.list_devices()
    for d in devices:
        if d.get("adopted") and not d.get("online"):
            findings.append({"severity": "warning", "area": "device",
                             "detail": f"{d.get('name')} ({d.get('model')}) is offline"})

    # Client-signal + AP-load analysis.
    clients = await agent.list_clients()
    weak = [c for c in clients if isinstance(c.get("signal_dbm"), (int, float))
            and c["signal_dbm"] <= -75 and not c.get("wired")]
    if weak:
        findings.append({"severity": "info", "area": "wifi",
                         "detail": f"{len(weak)} wireless client(s) at weak signal (<= -75 dBm)",
                         "clients": [c.get("name") or c.get("mac") for c in weak][:10]})

    # Radio config recommendations (only when classic API is available).
    if agent.settings.has_classic_auth():
        radios = await agent.radio_status()
        online_aps = [r for r in radios if r.get("online")]
        # Co-channel 2.4GHz check across APs.
        used_24: dict[Any, list[str]] = {}
        for ap in online_aps:
            for radio in ap.get("radios", []):
                if radio.get("band") == "2.4GHz":
                    ch = radio.get("channel")
                    used_24.setdefault(ch, []).append(ap.get("name"))
        for ch, aps in used_24.items():
            if isinstance(ch, int) and ch not in _CLEAN_24:
                recs.append({"area": "wifi", "priority": "medium",
                             "detail": f"2.4GHz channel {ch} on {aps} overlaps; prefer 1/6/11",
                             "suggested_op": {"op": "set_radio", "band": "2.4GHz"}})
        if len(online_aps) >= 2:
            for ch, aps in used_24.items():
                if len(aps) >= 2:
                    recs.append({"area": "wifi", "priority": "medium",
                                 "detail": f"{len(aps)} APs share 2.4GHz channel {ch} "
                                           f"({aps}); split them onto 1/6/11 to cut co-channel "
                                           f"interference"})

    # Speedtest freshness.
    try:
        last = await agent.speedtest_last()
        report["last_speedtest"] = last
    except Exception:
        pass

    report["summary"] = {
        "findings": len(findings),
        "recommendations": len(recs),
        "devices_online": overview.get("devices_online"),
        "device_count": overview.get("device_count"),
        "client_count": overview.get("client_count"),
    }
    return report


async def monitor(
    agent: UniFiAgent,
    *,
    interval_s: int = 300,
    iterations: int | None = None,
    sink: Any = None,
) -> None:
    """Run :func:`diagnostics_once` every ``interval_s`` seconds.

    ``iterations=None`` runs forever. ``sink`` is a callable taking the report dict; the
    default writes a JSONL line to stdout.
    """
    emit = sink or (lambda r: print(json.dumps(r, default=str)))
    count = 0
    while iterations is None or count < iterations:
        count += 1
        try:
            report = await diagnostics_once(agent)
            emit(report)
        except Exception as exc:  # noqa: BLE001 - a loop must survive transient errors
            log.warning("diagnostic pass failed: %s", exc)
            emit({"ts": datetime.now(UTC).isoformat(), "error": str(exc)})
        if iterations is not None and count >= iterations:
            break
        await asyncio.sleep(interval_s)
