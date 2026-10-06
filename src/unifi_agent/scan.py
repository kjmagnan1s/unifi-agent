"""Repeatable network evidence collection. Configuration is never changed here."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import shutil
import socket
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from .facade import UniFiAgent
from .history import History, compare, now
from .models import normalize_client, normalize_device


def pick(value: dict, keys: str) -> dict:
    return {k: value[k] for k in keys.split() if k in value}


def device_record(d: dict) -> dict:
    out = {
        **normalize_device(d),
        **pick(d, "last_seen disconnected_at upgradable overheating country_code"),
    }
    # Never persist whole device objects: they contain adoption/SSH credentials.
    out["uplink"] = pick(
        d.get("uplink", {}),
        "uplink_mac uplink_device_name uplink_remote_port "
        "port_idx type speed max_speed full_duplex up rx_bytes tx_bytes "
        "rx_errors tx_errors rx_dropped tx_dropped latency drops uptime",
    )
    out["ports"] = [
        pick(
            p,
            "port_idx name speed up full_duplex poe_enable poe_power "
            "rx_bytes tx_bytes rx_errors tx_errors rx_dropped tx_dropped",
        )
        for p in d.get("port_table", [])
    ]
    out["radio_stats"] = [
        pick(
            r,
            "name radio channel bw tx_power cu_total cu_self_rx cu_self_tx "
            "tx_retries_pct tx_packets tx_retries num_sta satisfaction state",
        )
        for r in d.get("radio_table_stats", [])
    ]
    out["temperatures"] = [pick(t, "name type value") for t in d.get("temperatures", [])]
    return out


def client_record(c: dict) -> dict:
    return {
        **normalize_client(c),
        **pick(
            c,
            "last_seen first_seen network_id network sw_mac "
            "sw_port wired_rate rx_bytes tx_bytes rx_packets tx_packets "
            "tx_retries wifi_tx_attempts wifi_tx_dropped radio_proto",
        ),
    }


def speed_result(s: dict) -> dict:
    out = pick(
        s, "rundate latency xput_download xput_upload status_download status_upload status_summary"
    )
    stamp = s.get("rundate", 0) or 0
    completed = (
        stamp > 0
        and s.get("status_download") == 2
        and s.get("status_upload") == 2
        and (s.get("xput_download") or 0) > 0
        and (s.get("xput_upload") or 0) > 0
    )
    out["valid"] = completed
    out["age_s"] = max(0, datetime.now(UTC).timestamp() - stamp) if stamp > 0 else None
    return out


def error_record(exc: Exception) -> dict:
    # No arbitrary response text, which can contain credentials or controller config.
    return {
        "type": type(exc).__name__,
        "http_status": getattr(exc, "status", None),
        "code": getattr(exc, "code", None),
    }


async def ping(target: str, count: int = 10) -> dict:
    """Pings a numeric address; no shell. ICMP unavailable is not proof the device is offline."""
    try:
        address = str(ipaddress.ip_address(target))
    except ValueError:
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(target, None, type=socket.SOCK_STREAM)
            address = str(ipaddress.ip_address(infos[0][4][0]))
        except (OSError, ValueError, IndexError):
            return {"target": target, "status": "invalid_target", "loss_pct": None, "mean_ms": None}
    executable = shutil.which("ping")
    if not executable:
        return {"target": target, "status": "unavailable"}
    process = await asyncio.create_subprocess_exec(
        executable,
        "-n",
        "-c",
        str(count),
        address,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env={"LC_ALL": "C", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
    )
    try:
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=count + 4)
    except TimeoutError:
        process.kill()
        await process.communicate()
        return {"target": target, "status": "timeout", "loss_pct": None}
    text = stdout.decode(errors="replace")
    loss = re.search(r"([\d.]+)% packet loss", text)
    times = re.findall(r"time[=<]([\d.]+)\s*ms", text)
    rtts = [float(t) for t in times]
    mean = sum(rtts) / len(rtts) if rtts else None
    return {
        "target": target,
        "status": "ok" if loss else "unavailable",
        "loss_pct": float(loss[1]) if loss else None,
        "sent": count,
        "received": len(rtts),
        "mean_ms": mean,
        "max_ms": max(rtts) if rtts else None,
        "rtts_ms": rtts,
    }


async def discovery(networks: list[dict]) -> dict:
    candidates = set()
    skipped = []
    for n in networks:
        if n.get("purpose") != "corporate" or not n.get("enabled", True):
            continue
        try:
            subnet = ipaddress.ip_network(n.get("ip_subnet", ""), strict=False)
            if subnet.version != 4 or not subnet.is_private or subnet.num_addresses > 512:
                skipped.append(str(subnet))
                continue
            candidates.update(str(ip) for ip in subnet.hosts())
        except ValueError:
            continue
    sem = asyncio.Semaphore(32)

    async def one(ip):
        async with sem:
            return await ping(ip, 1)

    rows = await asyncio.gather(*(one(ip) for ip in sorted(candidates)))
    return {
        "method": "one ICMP probe per private LAN IPv4 address, at most 512 per subnet",
        "probed": len(rows),
        "responded": [r["target"] for r in rows if r.get("received", 0)],
        "skipped_subnets": skipped,
        "note": "Non-response may mean ICMP filtering or sleep; not an offline verdict.",
    }


def assessment(scan: dict) -> dict:
    findings = []
    latest = (scan.get("samples") or [{}])[-1]
    for name, entry in scan.get("sources", {}).items():
        if entry["status"] != "ok":
            findings.append({"area": "collection", "source": name, "status": entry["status"]})
    clients = latest.get("clients", [])
    for d in latest.get("devices", []):
        if d.get("adopted") and not d.get("online"):
            findings.append(
                {
                    "area": "offline_inventory",
                    "name": d["name"],
                    "mac": d["mac"],
                    "note": "Verify whether expected online or intentionally retired.",
                }
            )
    weak = [
        pick(c, "name mac ip band signal_dbm")
        for c in clients
        if not c.get("wired")
        and isinstance(c.get("signal_dbm"), (int, float))
        and c["signal_dbm"] <= -75
    ]
    if weak:
        findings.append({"area": "weak_signal", "clients": weak})
    if not scan.get("speedtest", {}).get("valid"):
        findings.append({"area": "speedtest", "status": "no_valid_current_result"})
    for probe in scan.get("latency_idle", []):
        if probe.get("loss_pct") is not None and probe["loss_pct"] > 0:
            findings.append({"area": "packet_loss", **probe})
    return {
        "findings": findings,
        "counts": {
            "devices": len(latest.get("devices", []))
            if latest.get("collection", {}).get("devices") == "ok"
            else None,
            "clients": len(clients)
            if latest.get("collection", {}).get("clients") == "ok"
            else None,
            "weak_wireless_clients": len(weak)
            if latest.get("collection", {}).get("clients") == "ok"
            else None,
        },
        "interpretation": "Short samples; no continuous uptime or causal improvement claim.",
    }


async def collect(
    agent: UniFiAgent,
    history: History,
    *,
    samples: int = 3,
    interval: int = 20,
    active_speedtest: bool = False,
    discover: bool = False,
    probes: bool = True,
) -> dict[str, Any]:
    if not 1 <= samples <= 12 or not 0 <= interval <= 300:
        raise ValueError("samples must be 1..12 and interval 0..300 seconds")
    if active_speedtest and agent.settings.read_only:
        raise ValueError("Active speedtest requires write-enabled settings and explicit consent")
    previous = history.latest(agent.settings.host, agent.settings.site)
    scan = {
        "schema_version": 1,
        "id": str(uuid.uuid4()),
        "started_at": now(),
        "host": agent.settings.host,
        "site": agent.settings.site,
        "sources": {},
        "samples": [],
        "status": "collecting",
    }

    async def fetch(name, factory, project=lambda v: v):
        try:
            value = await factory()
            scan["sources"][name] = {"status": "ok", "at": now()}
            return project(value)
        except Exception as exc:
            scan["sources"][name] = {"status": "unavailable", "at": now(), **error_record(exc)}
            return None

    try:
        await agent.transport.start()
        c = agent._require_classic()
        # These reads are sequential to avoid competing logins and rate-limit bursts.
        for index in range(samples):
            entry = {"at": now(), "collection": {}}
            for name, factory, project in (
                ("devices", c.devices, lambda rows: [device_record(d) for d in rows]),
                ("clients", c.clients, lambda rows: [client_record(d) for d in rows]),
                (
                    "health",
                    c.health,
                    lambda rows: [
                        pick(
                            d,
                            "subsystem status latency uptime drops "
                            "num_user num_sta num_ap num_adopted",
                        )
                        for d in rows
                    ],
                ),
            ):
                value = await fetch(f"sample_{index}_{name}", factory, project)
                entry["collection"][name] = "ok" if value is not None else "unavailable"
                entry[name] = value or []
            scan["samples"].append(entry)
            if index < samples - 1:
                await asyncio.sleep(interval)

        specs = [
            ("sysinfo", c.sysinfo, lambda d: pick(d, "version build uptime timezone")),
            ("known_clients", c.all_clients, lambda rows: [client_record(d) for d in rows]),
            (
                "networks",
                c.networkconf,
                lambda rows: [
                    pick(
                        d,
                        "_id name purpose enabled ip_subnet "
                        "vlan vlan_enabled dhcpd_enabled dhcpd_start dhcpd_stop wan_type wan_networkgroup "
                        "wan_load_balance_type wan_smartq_enabled wan_smartq_up_rate wan_smartq_down_rate",
                    )
                    for d in rows
                ],
            ),
            (
                "wlans",
                c.wlanconf,
                lambda rows: [
                    pick(
                        d,
                        "_id name enabled security wpa_mode "
                        "wpa3_support pmf_mode networkconf_id wlan_band wlan_bands is_guest l2_isolation "
                        "bss_transition fast_roaming_enabled minrate_ng_enabled minrate_na_enabled",
                    )
                    for d in rows
                ],
            ),
            (
                "settings",
                lambda: c.get("/rest/setting"),
                lambda rows: [
                    pick(d, "key enabled ips_mode upnp_enabled dpi_enabled mdns_enabled")
                    for d in rows
                ],
            ),
            (
                "port_forwards",
                c.port_forwards,
                lambda rows: [
                    pick(d, "name enabled proto dst_port fwd_port fwd src") for d in rows
                ],
            ),
            (
                "legacy_firewall",
                c.firewall_rules,
                lambda rows: [
                    pick(d, "name enabled action ruleset protocol rule_index") for d in rows
                ],
            ),
            (
                "events",
                lambda: c.get("/stat/event?_limit=200&_sort=-time&within=168"),
                lambda rows: [
                    pick(d, "time datetime key msg subsystem ap_displayName") for d in rows
                ],
            ),
            (
                "alarms",
                c.alarms,
                lambda rows: [pick(d, "time datetime key msg archived") for d in rows],
            ),
            (
                "neighbor_aps",
                c.rogue_aps,
                lambda rows: [
                    pick(d, "bssid essid channel signal rssi radio last_seen") for d in rows
                ],
            ),
            ("dpi", c.dpi, lambda rows: [pick(d, "by_cat by_app last_updated") for d in rows]),
            ("speedtest_last", c.speedtest_status, speed_result),
        ]
        for name, factory, project in specs:
            scan[name] = await fetch(name, factory, project)
            if scan[name] is not None and name in {"dpi", "neighbor_aps"} and not any(scan[name]):
                scan["sources"][name]["status"] = "no_data"
        if agent.settings.has_integration_auth():
            scan["integration_info"] = await fetch(
                "integration_info",
                agent.integration.info,
                lambda d: pick(d, "applicationVersion version"),
            )
        start = datetime.now(UTC) - timedelta(days=7)
        scan["hourly_site"] = await fetch(
            "hourly_site",
            lambda: c.report(
                "hourly",
                "site",
                attrs=["time", "wan-rx_bytes", "wan-tx_bytes", "num_sta", "latency"],
                start_ms=int(start.timestamp() * 1000),
                end_ms=int(datetime.now(UTC).timestamp() * 1000),
            ),
            lambda rows: [pick(d, "time wan-rx_bytes wan-tx_bytes num_sta latency") for d in rows],
        )
        scan["usage_coverage"] = {
            "requested_start": start.isoformat(),
            "rows": len(scan.get("hourly_site") or []),
            "hourly_timestamps": [r.get("time") for r in scan.get("hourly_site") or []],
            "latency_rows": sum("latency" in r for r in scan.get("hourly_site") or []),
            "note": "Controller hourly aggregates; do not substitute for ISP billing or continuous uptime.",
        }
        scan["speedtest"] = scan.get("speedtest_last") or {"valid": False}
        host = httpx.URL(agent.settings.base_url).host
        targets = [host, "1.1.1.1", "8.8.8.8"]
        if probes:
            scan["latency_idle"] = await asyncio.gather(*(ping(t) for t in targets))
        if discover:
            scan["discovery"] = await discovery(scan.get("networks") or [])
        if active_speedtest:
            # Capture a probe train during the test, separately from the idle baseline.
            async def run_test():
                return await fetch(
                    "active_speedtest", lambda: agent.run_speedtest(confirm=True, timeout_s=120)
                )

            if probes:
                result, loaded = await asyncio.gather(
                    run_test(), asyncio.gather(*(ping(t, 45) for t in targets))
                )
                scan["latency_during_speedtest"] = loaded
            else:
                result = await run_test()
            scan["active_speedtest"] = result
            final = await fetch("speedtest_after", c.speedtest_status, speed_result)
            scan["speedtest"] = final or {"valid": False}
            scan["speedtest"]["new_this_scan"] = bool(
                final
                and final.get("valid")
                and final.get("rundate", 0)
                >= datetime.fromisoformat(scan["started_at"]).timestamp()
            )
    except Exception as exc:
        scan["sources"]["connection"] = {"status": "unavailable", **error_record(exc)}
    finally:
        await agent.transport.aclose()
    core_ok = bool(scan["samples"]) and all(
        all(v == "ok" for v in s["collection"].values()) for s in scan["samples"]
    )
    scan["status"] = (
        "complete"
        if core_ok and all(s["status"] == "ok" for s in scan["sources"].values())
        else ("partial" if core_ok else "failed")
    )
    scan["finished_at"] = now()
    scan["comparison"] = compare(previous, scan)
    scan["assessment"] = assessment(scan)
    history.save(scan)
    return scan
