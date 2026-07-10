"""Normalizers that turn raw UniFi payloads into small, stable, LLM-friendly dicts.

The raw device/client objects have 100+ fields each; feeding them wholesale to a model
wastes context and leaks internal churn. These helpers project the fields that matter and
give them consistent names across the two APIs.

Note: client hostnames, SSIDs, and device names are user/attacker-controllable strings.
They are passed through as data; never treat them as instructions.
"""

from __future__ import annotations

from typing import Any

_RADIO_BAND = {"ng": "2.4GHz", "na": "5GHz", "6e": "6GHz", "ax": "6GHz"}


def normalize_device(d: dict[str, Any]) -> dict[str, Any]:
    radios = []
    for rt in d.get("radio_table", []) or []:
        radios.append(
            {
                "band": _RADIO_BAND.get(rt.get("radio"), rt.get("radio")),
                "radio": rt.get("radio"),
                "name": rt.get("name"),
                "channel": rt.get("channel"),
                "width_mhz": rt.get("ht"),
                "tx_power_mode": rt.get("tx_power_mode"),
                "tx_power": rt.get("tx_power"),
            }
        )
    return {
        "id": d.get("_id"),
        "mac": d.get("mac"),
        "name": d.get("name") or d.get("hostname"),
        "model": d.get("model"),
        "type": d.get("type"),
        "online": d.get("state") == 1,
        "adopted": d.get("adopted"),
        "version": d.get("version"),
        "uptime_s": d.get("uptime"),
        "clients": d.get("num_sta"),
        "cpu_pct": _to_float(d.get("system-stats", {}).get("cpu")),
        "mem_pct": _to_float(d.get("system-stats", {}).get("mem")),
        "radios": radios,
    }


def normalize_client(c: dict[str, Any]) -> dict[str, Any]:
    return {
        "mac": c.get("mac"),
        "name": c.get("name") or c.get("hostname") or c.get("oui"),
        "hostname": c.get("hostname"),
        "ip": c.get("ip"),
        "wired": bool(c.get("is_wired")),
        "ap_mac": c.get("ap_mac"),
        "essid": c.get("essid"),
        "band": _RADIO_BAND.get(c.get("radio"), c.get("radio")),
        "channel": c.get("channel"),
        "signal_dbm": c.get("signal"),
        "rssi": c.get("rssi"),
        "tx_rate_kbps": c.get("tx_rate"),
        "rx_rate_kbps": c.get("rx_rate"),
        "uptime_s": c.get("uptime"),
        "blocked": bool(c.get("blocked")),
        "guest": bool(c.get("is_guest")),
        "satisfaction": c.get("satisfaction"),
    }


def normalize_health(rows: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for r in rows:
        sub = r.get("subsystem")
        if not sub:
            continue
        entry = {"status": r.get("status")}
        for k in ("num_user", "num_guest", "num_sta", "latency", "xput_up", "xput_down",
                  "speedtest_ping", "gw_system-stats", "num_ap", "num_adopted"):
            if k in r:
                entry[k] = r[k]
        out[sub] = entry
    return out


def _to_float(v: Any) -> float | None:
    try:
        return round(float(v), 1)
    except (TypeError, ValueError):
        return None
