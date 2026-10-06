"""Bounded maintenance experiments with persisted recovery data.

The weekly agent chooses a hypothesis. This module enforces the time window,
backup, narrow setting scope and rollback mechanics. It never invents a change.
"""

from __future__ import annotations

import asyncio
import copy
import os
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from .errors import UniFiAgentError
from .history import History
from .operations import OPERATIONS
from .scan import collect, ping

CENTRAL = ZoneInfo("America/Chicago")
QUEUE_KEYS = {"wan_smartq_enabled", "wan_smartq_up_rate", "wan_smartq_down_rate"}
RADIO_KEYS = {"channel", "ht", "tx_power_mode", "tx_power"}


def _norm(value: Any) -> Any:
    return int(value) if isinstance(value, str) and value.isdigit() else value


def _settings(plan: dict, settings: dict) -> dict:
    keys = RADIO_KEYS if plan["kind"] == "radio" else QUEUE_KEYS
    return {k: _norm(settings[k]) for k in keys if k in settings}


def _matches(settings: dict, expected: dict) -> bool:
    return all(settings.get(k) == v for k, v in expected.items())


def _operation(plan: dict):
    return OPERATIONS["set_radio" if plan["kind"] == "radio" else "update_wan_queue"]


def in_window(at: datetime | None = None) -> bool:
    local = (at or datetime.now(UTC)).astimezone(CENTRAL)
    return local.weekday() == 1 and local.hour == 2


def validate_plan(plan: dict, baseline: dict, at: datetime | None = None) -> None:
    at = at or datetime.now(UTC)
    if not in_window(at):
        raise UniFiAgentError(
            "Automatic changes are limited to Tuesday 02:00-03:00 America/Chicago"
        )
    age = (at - datetime.fromisoformat(baseline["finished_at"])).total_seconds()
    if (
        age < 0
        or age > 1800
        or baseline["status"] == "failed"
        or len(baseline.get("samples", [])) < 3
    ):
        raise UniFiAgentError("A baseline with three samples from the last 30 minutes is required")
    if not plan.get("reason") or not plan.get("success_criteria") or not plan.get("evidence"):
        raise UniFiAgentError("Plan requires reason, evidence and measurable success_criteria")
    if plan.get("kind") not in {"radio", "smartq"}:
        raise UniFiAgentError("Supported experiments: radio or smartq")
    changes = plan.get("changes", {})
    keys = RADIO_KEYS if plan["kind"] == "radio" else QUEUE_KEYS
    if not changes or set(changes) - keys:
        raise UniFiAgentError("Unsupported or empty setting change")
    if plan["kind"] == "radio":
        if plan.get("band") not in {"ng", "na"}:
            raise UniFiAgentError("Automatic radio experiments support 2.4/5 GHz only")
        channels = {1, 6, 11} if plan["band"] == "ng" else {36, 40, 44, 48, 149, 153, 157, 161}
        if "channel" in changes and (
            type(changes["channel"]) is not int or changes["channel"] not in channels
        ):
            raise UniFiAgentError("Use an explicit non-DFS US channel")
        widths = {20} if plan["band"] == "ng" else {40, 80}
        if "ht" in changes and (type(changes["ht"]) is not int or changes["ht"] not in widths):
            raise UniFiAgentError("Unsupported automatic channel width")
        if changes.get("tx_power_mode", "auto") not in {"auto", "low", "medium", "high", "custom"}:
            raise UniFiAgentError("Invalid transmit-power mode")
        if "tx_power" in changes and (
            type(changes["tx_power"]) is not int or not 8 <= changes["tx_power"] <= 23
        ):
            raise UniFiAgentError("Automatic transmit power must be 8..23 dBm")
        if "tx_power" in changes and changes.get("tx_power_mode") != "custom":
            raise UniFiAgentError("Explicit power requires custom mode")
        if changes.get("tx_power_mode") == "custom" and "tx_power" not in changes:
            raise UniFiAgentError("Custom mode requires explicit power")
    else:
        if not baseline.get("speedtest", {}).get("new_this_scan"):
            raise UniFiAgentError("Smart Queue experiments require a completed baseline speedtest")
        if "wan_smartq_enabled" in changes and type(changes["wan_smartq_enabled"]) is not bool:
            raise UniFiAgentError("Smart Queues enabled must be a boolean")
        for key in QUEUE_KEYS - {"wan_smartq_enabled"}:
            if key in changes and (
                type(changes[key]) is not int or not 1000 <= changes[key] <= 2500000
            ):
                raise UniFiAgentError("Queue limits must be integer kbps within 1..2500 Mbps")
    for sample in baseline["samples"]:
        if any(
            sample.get("collection", {}).get(k) != "ok" for k in ("devices", "clients", "health")
        ):
            raise UniFiAgentError("Cannot tune with incomplete core telemetry")
        if any(
            h.get("status") != "ok"
            for h in sample.get("health", [])
            if h.get("subsystem") in {"wan", "www"}
        ):
            raise UniFiAgentError("Restore WAN health before tuning")
    probes = baseline.get("latency_idle", [])
    if len(probes) < 3 or any(p.get("loss_pct") != 0 or p.get("mean_ms") is None for p in probes):
        raise UniFiAgentError("Three healthy idle latency probes required before an experiment")


async def _target(agent, plan: dict) -> tuple[dict, dict]:
    c = agent._require_classic()
    if plan["kind"] == "radio":
        device = await c.device(plan["target"])
        if device.get("type") != "uap" or device.get("state") != 1:
            raise UniFiAgentError("Target must be an online AP")
        if device.get("model") != "UAPL6" or device.get("country_code") != 840:
            raise UniFiAgentError("Automatic radio tuning currently validates US U6+ hardware only")
        radios = [r for r in device.get("radio_table", []) if r.get("radio") == plan["band"]]
        if len(radios) != 1:
            raise UniFiAgentError("Target radio is ambiguous")
        return device, radios[0]
    networks = await c.networkconf()
    matches = [
        n
        for n in networks
        if n.get("_id") == plan["target"]
        and n.get("purpose") == "wan"
        and n.get("wan_networkgroup") == "WAN"
    ]
    if len(matches) != 1:
        raise UniFiAgentError("Target must be the existing primary WAN")
    return matches[0], matches[0]


async def _unchanged(agent, plan: dict, expected: dict) -> dict:
    """Re-fetch and reject drift before any write."""
    target, settings = await _target(agent, plan)
    if _settings(plan, settings) != expected:
        raise UniFiAgentError(
            "Settings changed since preview; refusing to overwrite concurrent edits"
        )
    return target


async def _put(agent, plan: dict, target: dict, replacement: dict, *, recovery: bool) -> None:
    """Guarded, audited write that preserves fields outside the experiment."""
    details = {"target": plan["target"], "kind": plan["kind"], "settings": replacement}
    agent.guard.evaluate(
        _operation(plan), confirm=True, dry_run=False,
        override_blast_radius=recovery, details=details,
    )
    if plan["kind"] == "radio":
        table = copy.deepcopy(target["radio_table"])
        radio = next(r for r in table if r.get("radio") == plan["band"])
        for k in RADIO_KEYS:
            radio.pop(k, None)
        radio.update(replacement)
        await agent.classic.put_device(target["_id"], {"radio_table": table})
    else:
        # Queue keys must all be present in the original so rollback is exact.
        await agent.classic.put(f"/rest/networkconf/{target['_id']}", replacement)
    agent.audit.record("mutation.result", {"operation": _operation(plan).name, "details": details})


async def _write(
    agent, plan: dict, expected: dict, replacement: dict, *, recovery: bool = False
) -> None:
    target = await _unchanged(agent, plan, expected)
    await _put(agent, plan, target, replacement, recovery=recovery)


async def _restore(agent, plan: dict, before: dict, after: dict) -> None:
    """Return to ``before``; a target already there needs no write."""
    _, settings = await _target(agent, plan)
    if _matches(_settings(plan, settings), before):
        return
    await _write(agent, plan, after, before, recovery=True)
    await asyncio.sleep(60)
    _, restored = await _target(agent, plan)
    if not _matches(_settings(plan, restored), before):
        raise UniFiAgentError("Rollback read-back mismatch")


async def experiment(agent, history: History, plan: dict) -> dict[str, Any]:
    with history.maintenance_lock():
        return await _experiment(agent, history, plan)


async def _experiment(agent, history: History, plan: dict) -> dict[str, Any]:
    baseline = history.get(plan["baseline_id"])
    validate_plan(plan, baseline)
    if agent.settings.read_only:
        raise UniFiAgentError("Maintenance is disabled by UNIFI_READ_ONLY")
    if (baseline["host"], baseline["site"]) != (agent.settings.host, agent.settings.site):
        raise UniFiAgentError("Baseline belongs to another network")
    agent.guard.evaluate(
        _operation(plan), confirm=False, dry_run=True,
        details={"target": plan.get("target"), "kind": plan["kind"]},
    )
    recent = datetime.now(UTC) - timedelta(days=6)
    for prior in history.experiments():
        statuses = {e["status"] for e in prior["events"]}
        if (
            statuses & {"applying", "applied"}
            and datetime.fromisoformat(prior["created_at"]) > recent
        ):
            raise UniFiAgentError(
                "One automatic experiment per week; assess the prior change first"
            )
        if statuses & {"applying", "applied"} and prior["events"][-1]["status"] not in {
            "accepted",
            "rolled_back",
        }:
            raise UniFiAgentError("Unresolved experiment requires recovery or assessment first")
    await agent.transport.start()
    _, settings = await _target(agent, plan)
    before = _settings(plan, settings)
    if plan["kind"] == "radio":
        base_device = next(
            (d for d in baseline["samples"][-1]["devices"] if d.get("mac") == plan["target"]), None
        )
        base_radio = next(
            (r for r in (base_device or {}).get("radios", []) if r.get("radio") == plan["band"]),
            None,
        )
        if not base_radio:
            raise UniFiAgentError("Target absent from baseline")
        for source, dest in (
            ("channel", "channel"),
            ("width_mhz", "ht"),
            ("tx_power_mode", "tx_power_mode"),
            ("tx_power", "tx_power"),
        ):
            if _norm(base_radio.get(source)) != before.get(dest):
                raise UniFiAgentError("Radio configuration drifted since baseline")
    else:
        base_network = next(
            (n for n in baseline.get("networks", []) if n.get("_id") == plan["target"]), {}
        )
        if any(_norm(base_network.get(k)) != before.get(k) for k in QUEUE_KEYS):
            raise UniFiAgentError("WAN configuration drifted since baseline")
    if plan["kind"] == "smartq" and set(before) != QUEUE_KEYS:
        raise UniFiAgentError("All original queue settings must be present for exact rollback")
    after = {**before, **plan["changes"]}
    if after == before:
        raise UniFiAgentError("No-op experiment refused")
    identifier = history.experiment(
        baseline["id"], plan["kind"], plan["reason"], {**plan, "before": before, "after": after}
    )
    # Persist and download a recovery point before touching any settings.
    try:
        rows = await agent.classic.create_backup()
        filename = next(
            (r.get("filename") or r.get("url") for r in rows if r.get("filename") or r.get("url")),
            None,
        )
        if not filename:
            raise UniFiAgentError("Backup did not provide a downloadable restore point")
        content = await agent.classic.download_backup(filename)
        if len(content) < 128 or content.lstrip().startswith((b"<", b"{")):
            raise UniFiAgentError("Backup download is empty or not an archive")
        backup_dir = history.path.parent / "backups"
        backup_dir.mkdir(mode=0o700, exist_ok=True)
        backup_path = backup_dir / f"{identifier}.unf"
        fd = os.open(backup_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        history.event(identifier, "backed_up", {"path": str(backup_path)})
    except Exception:
        history.event(identifier, "aborted", {"stage": "backup"})
        raise
    if not in_window():
        history.event(identifier, "aborted", {"stage": "maintenance_window_closed"})
        raise UniFiAgentError("Maintenance window closed while making backup")
    try:
        target = await _unchanged(agent, plan, before)
    except Exception:
        history.event(identifier, "aborted", {"stage": "drift_check"})
        raise
    history.event(identifier, "applying", {})
    try:
        await _put(agent, plan, target, after, recovery=False)
        history.event(identifier, "applied", {})
        await asyncio.sleep(60)
        _, actual = await _target(agent, plan)
        if not _matches(_settings(plan, actual), after):
            raise UniFiAgentError("Controller read-back does not match experiment")
        probes = await asyncio.gather(*(ping(p["target"]) for p in baseline["latency_idle"]))
        for old, new in zip(baseline["latency_idle"], probes, strict=True):
            if (
                new.get("loss_pct") != 0
                or new.get("mean_ms") is None
                or new["mean_ms"] > max(old["mean_ms"] * 2, old["mean_ms"] + 15)
            ):
                raise UniFiAgentError("Post-change latency/loss regressed or became unavailable")
        post = await collect(
            agent, history, samples=3, interval=20, active_speedtest=plan["kind"] == "smartq"
        )
        if post["status"] == "failed":
            raise UniFiAgentError("Post-change collection failed")
        initial = baseline["samples"][-1]
        final = post["samples"][-1]
        online_before = {d["mac"] for d in initial["devices"] if d.get("online")}
        online_after = {d["mac"] for d in final["devices"] if d.get("online")}
        if (
            not online_before <= online_after
            or len(final["clients"]) < len(initial["clients"]) * 0.8
        ):
            raise UniFiAgentError("Post-change device or client availability regressed")
        if any(
            h.get("status") != "ok" for h in final["health"] if h.get("subsystem") in {"wan", "www"}
        ):
            raise UniFiAgentError("Post-change WAN health regressed")
        if plan["kind"] == "smartq" and not post.get("speedtest", {}).get("new_this_scan"):
            raise UniFiAgentError("No valid post-change WAN performance test")
        history.event(identifier, "pending_assessment", {"post_scan_id": post["id"]})
        return {
            "experiment_id": identifier,
            "status": "pending_assessment",
            "post_scan_id": post["id"],
            "next": "Assess success_criteria now; accept only measured benefit, otherwise rollback.",
        }
    except Exception as exc:
        history.event(identifier, "verification_failed", {"error_type": type(exc).__name__})
        try:
            await agent.transport.start()
            await _restore(agent, plan, before, after)
            history.event(identifier, "rolled_back", {"reason": "verification_failed"})
        except Exception as rollback_error:
            history.event(
                identifier, "recovery_required", {"error_type": type(rollback_error).__name__}
            )
        raise


async def rollback(agent, history: History, identifier: str) -> None:
    with history.maintenance_lock():
        await _rollback(agent, history, identifier)


async def _rollback(agent, history: History, identifier: str) -> None:
    entry = history.experiment_entry(identifier)
    if agent.settings.read_only:
        raise UniFiAgentError("Rollback is disabled by UNIFI_READ_ONLY")
    baseline = history.get(entry["baseline_id"])
    if (baseline["host"], baseline["site"]) != (agent.settings.host, agent.settings.site):
        raise UniFiAgentError("Experiment belongs to another network")
    plan = entry["plan"]
    await agent.transport.start()
    await _restore(agent, plan, plan["before"], plan["after"])
    history.event(identifier, "rolled_back", {"reason": "assessment"})
