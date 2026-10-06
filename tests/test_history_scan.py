from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest

from unifi_agent.errors import UniFiAgentError
from unifi_agent.facade import UniFiAgent
from unifi_agent.history import History, compare, counter_delta
from unifi_agent.maintenance import _write, experiment, in_window, validate_plan
from unifi_agent.scan import assessment, collect, device_record, speed_result


def snapshot(identifier="s1", at="2026-09-15T07:00:00+00:00"):
    return {
        "id": identifier,
        "host": "10.0.0.1",
        "site": "default",
        "status": "partial",
        "started_at": at,
        "finished_at": at,
        "samples": [
            {
                "at": at,
                "collection": {"clients": "ok", "devices": "ok", "health": "ok"},
                "clients": [{"mac": "c1", "rx_bytes": 100, "tx_bytes": 50, "uptime_s": 1000}],
                "devices": [],
                "health": [{"subsystem": "wan", "status": "ok"}],
            }
            for _ in range(3)
        ],
        "latency_idle": [
            {"target": t, "loss_pct": 0, "mean_ms": 4} for t in ["10.0.0.1", "1.1.1.1", "8.8.8.8"]
        ],
    }


def test_persistence_redaction_and_reopen(tmp_path):
    path = tmp_path / "history.sqlite3"
    s = snapshot()
    s["nested"] = {"password": "do-not-store"}
    with History(path) as h:
        h.save(s)
        e = h.experiment("s1", "radio", "coverage", {"before": {"channel": 1}})
        h.event(e, "aborted", {"reason": "backup"})
        h.review("s1", {"decision": "no change"})
    with History(path) as h:
        assert h.get("s1")["nested"]["password"] == "***REDACTED***"
        assert h.latest("other", "default") is None
        assert h.latest("10.0.0.1", "default")["id"] == "s1"
        assert h.experiments()[0]["events"][-1]["status"] == "aborted"
        assert h.db.execute("select count(*) from reviews").fetchone()[0] == 1
    assert path.stat().st_mode & 0o777 == 0o600
    assert b"do-not-store" not in path.read_bytes()


def test_comparison_counter_reset_and_missing_not_zero():
    assert (
        counter_delta(
            {"rx_bytes": 100, "uptime_s": 1000}, {"rx_bytes": 150, "uptime_s": 1060}, 60, "rx_bytes"
        )["value"]
        == 50
    )
    assert (
        counter_delta(
            {"rx_bytes": 100, "uptime_s": 1000},
            {"rx_bytes": 1000, "uptime_s": 1100},
            86400,
            "rx_bytes",
        )["value"]
        is None
    )
    assert counter_delta({}, {}, 60, "rx_bytes")["value"] is None
    old = snapshot()
    new = snapshot("s2", "2026-09-15T07:01:00+00:00")
    new["samples"][-1]["collection"]["clients"] = "unavailable"
    assert compare(old, new)["not_observed_now"] is None


def test_snapshot_does_not_export_device_credentials():
    d = device_record(
        {
            "name": "AP",
            "x_authkey": "secret",
            "radio_table": [],
            "uplink": {"password": "secret", "speed": 1000},
        }
    )
    assert "secret" not in json.dumps(d)
    assert d["uplink"]["speed"] == 1000


def test_failed_assessment_reports_unknown_inventory():
    report = assessment({"samples": [], "sources": {"connection": {"status": "unavailable"}}})
    assert report["counts"]["clients"] is None
    assert report["findings"][0]["area"] == "collection"


def test_speed_result_rejects_empty_incomplete_and_accepts_completed():
    assert not speed_result({"rundate": 0})["valid"]
    assert not speed_result({"rundate": 100, "xput_download": 400, "xput_upload": 5})["valid"]
    assert speed_result(
        {
            "rundate": 100,
            "xput_download": 400,
            "xput_upload": 5,
            "status_download": 2,
            "status_upload": 2,
        }
    )["valid"]


async def test_connection_failure_is_saved(settings, tmp_path):
    a = UniFiAgent(settings)
    a.transport.start = AsyncMock(side_effect=RuntimeError("secret-message"))
    with History(tmp_path / "h.db") as h:
        result = await collect(a, h, samples=1, interval=0, probes=False)
        assert result["status"] == "failed"
        assert h.get(result["id"])["sources"]["connection"]["type"] == "RuntimeError"
        assert "secret-message" not in json.dumps(h.get(result["id"]))


async def test_partial_optional_sources_keeps_core_inventory(settings, tmp_path):
    a = UniFiAgent(settings)
    a.transport.start = AsyncMock()
    a.transport.aclose = AsyncMock()
    c = AsyncMock()
    c.devices.return_value = [{"mac": "ap", "name": "AP", "state": 1}]
    c.clients.return_value = [{"mac": "client", "signal": -85}]
    c.health.return_value = [{"subsystem": "wan", "status": "ok"}]
    c.sysinfo.return_value = {"version": "10"}
    for name in [
        "all_clients",
        "networkconf",
        "wlanconf",
        "port_forwards",
        "firewall_rules",
        "rogue_aps",
        "dpi",
        "report",
    ]:
        getattr(c, name).return_value = []
    c.get.side_effect = RuntimeError("endpoint missing")
    c.alarms.side_effect = RuntimeError("endpoint missing")
    c.speedtest_status.return_value = {}
    a._classic = c
    a._integration = AsyncMock()
    a._integration.info.side_effect = RuntimeError("401")
    with History(tmp_path / "h.db") as h:
        result = await collect(a, h, samples=3, interval=0, probes=False)
        assert result["status"] == "partial"
        assert result["assessment"]["counts"]["clients"] == 1
        assert result["assessment"]["counts"]["weak_wireless_clients"] == 1
        assert result["sources"]["events"]["status"] == "unavailable"
        assert len(h.get(result["id"])["samples"]) == 3


def plan():
    return {
        "kind": "radio",
        "target": "ap",
        "band": "ng",
        "changes": {"channel": 6},
        "baseline_id": "s1",
        "reason": "measured contention",
        "evidence": ["s1"],
        "success_criteria": "lower retries without loss",
    }


def test_maintenance_window_tracks_dst():
    assert in_window(datetime(2026, 9, 15, 7, tzinfo=UTC))
    assert in_window(datetime(2026, 12, 15, 8, tzinfo=UTC))
    assert not in_window(datetime(2026, 9, 15, 8, tzinfo=UTC))


@pytest.mark.parametrize(
    "change",
    [
        {"channel": 149},
        {"ht": 80},
        {"tx_power": 30},
        {"password": "anything"},
        {"tx_power_mode": "custom"},
    ],
)
def test_invalid_radio_plan_refused(change):
    p = plan()
    p["changes"] = change
    with pytest.raises(UniFiAgentError):
        validate_plan(p, snapshot(), datetime(2026, 9, 15, 7, 1, tzinfo=UTC))


def test_stale_or_incomplete_baseline_refused():
    at = datetime(2026, 9, 15, 7, 1, tzinfo=UTC)
    validate_plan(plan(), snapshot(), at)
    s = snapshot()
    s["latency_idle"] = []
    with pytest.raises(UniFiAgentError):
        validate_plan(plan(), s, at)
    s = snapshot()
    s["finished_at"] = (at - timedelta(hours=1)).isoformat()
    with pytest.raises(UniFiAgentError):
        validate_plan(plan(), s, at)


async def test_write_rejects_config_drift_and_preserves_other_band(settings):
    a = UniFiAgent(settings)
    c = AsyncMock()
    a._classic = c
    c.device.return_value = {
        "_id": "id",
        "type": "uap",
        "model": "UAPL6",
        "country_code": 840,
        "state": 1,
        "radio_table": [
            {"radio": "ng", "channel": 1, "ht": 20},
            {"radio": "na", "channel": 149, "ht": 80},
        ],
    }
    with pytest.raises(UniFiAgentError):
        await _write(a, plan(), {"channel": 11, "ht": 20}, {"channel": 6, "ht": 20})
    c.put_device.assert_not_called()
    await _write(a, plan(), {"channel": 1, "ht": 20}, {"channel": 6, "ht": 20})
    assert c.put_device.call_args.args[1]["radio_table"][1]["channel"] == 149


async def test_required_backup_failure_prevents_experiment_write(settings, tmp_path, monkeypatch):
    import unifi_agent.maintenance as maintenance

    a = UniFiAgent(settings)
    a.transport.start = AsyncMock()
    c = AsyncMock()
    a._classic = c
    monkeypatch.setattr(maintenance, "validate_plan", lambda *args: None)
    monkeypatch.setattr(maintenance, "in_window", lambda: True)
    c.device.return_value = {
        "_id": "id",
        "type": "uap",
        "model": "UAPL6",
        "country_code": 840,
        "state": 1,
        "radio_table": [{"radio": "ng", "channel": 1, "ht": 20}],
    }
    c.create_backup.side_effect = RuntimeError("failed")
    s = snapshot()
    for sample in s["samples"]:
        sample["devices"] = [
            {"mac": "ap", "radios": [{"radio": "ng", "channel": 1, "width_mhz": 20}]}
        ]
    with History(tmp_path / "h.db") as h:
        h.save(s)
        with pytest.raises(RuntimeError):
            await experiment(a, h, plan())
        assert h.experiments()[0]["events"][-1]["status"] == "aborted"
    c.put_device.assert_not_called()


async def test_failed_verification_rolls_back_and_records_outcome(settings, tmp_path, monkeypatch):
    import unifi_agent.maintenance as maintenance

    a = UniFiAgent(settings)
    a.transport.start = AsyncMock()
    c = AsyncMock()
    a._classic = c
    monkeypatch.setattr(maintenance, "validate_plan", lambda *args: None)
    monkeypatch.setattr(maintenance, "in_window", lambda: True)
    monkeypatch.setattr(maintenance.asyncio, "sleep", AsyncMock())
    monkeypatch.setattr(maintenance, "ping", AsyncMock(return_value={"loss_pct": 100}))
    device = {
        "_id": "id",
        "type": "uap",
        "model": "UAPL6",
        "country_code": 840,
        "state": 1,
        "radio_table": [{"radio": "ng", "channel": 1, "ht": 20}],
    }
    c.device.side_effect = lambda *args: deepcopy(device)

    async def put(identifier, payload):
        device["radio_table"] = deepcopy(payload["radio_table"])

    c.put_device.side_effect = put
    c.create_backup.return_value = [{"filename": "backup.unf"}]
    c.download_backup.return_value = b"x" * 256
    s = snapshot()
    for sample in s["samples"]:
        sample["devices"] = [
            {"mac": "ap", "radios": [{"radio": "ng", "channel": 1, "width_mhz": 20}]}
        ]
    with History(tmp_path / "h.db") as h:
        h.save(s)
        with pytest.raises(UniFiAgentError):
            await experiment(a, h, plan())
        assert h.experiments()[0]["events"][-1]["status"] == "rolled_back"
    assert device["radio_table"][0]["channel"] == 1
    assert c.put_device.call_count == 2


def test_read_only_history_and_reviews(tmp_path):
    path = tmp_path / "h.db"
    with History(path) as h:
        h.save(snapshot())
        h.review("s1", {"decision": "baseline_only"})
    with History(path, read_only=True) as h:
        assert h.reviews("s1")[0]["payload"]["decision"] == "baseline_only"
        assert h.reviews("missing") == []


def test_smart_queue_requires_completed_baseline_test():
    p = plan()
    p["kind"] = "smartq"
    p["changes"] = {"wan_smartq_enabled": False}
    at = datetime(2026, 9, 15, 7, 1, tzinfo=UTC)
    with pytest.raises(UniFiAgentError, match="completed baseline speedtest"):
        validate_plan(p, snapshot(), at)
    s = snapshot()
    s["speedtest"] = {"new_this_scan": True}
    validate_plan(p, s, at)


def test_maintenance_lock_rejects_competing_processes(tmp_path):
    with (
        History(tmp_path / "h.db") as a, History(tmp_path / "h.db") as b,
        a.maintenance_lock(), pytest.raises(BlockingIOError), b.maintenance_lock(),
    ):
        pass
