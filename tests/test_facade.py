from __future__ import annotations

import pytest

from unifi_agent.errors import BlastRadiusError, ReadOnlyError
from unifi_agent.facade import UniFiAgent
from unifi_agent.safety import BlastRadius


class FakeClassic:
    """Stand-in for ClassicClient that records calls instead of hitting the network."""

    def __init__(self):
        self.puts = []
        self.blocked = []
        self.backups = 0
        self._device = {
            "_id": "dev1", "mac": "aa:bb:cc:00:00:01", "name": "Main Floor U6+", "type": "uap",
            "state": 1, "radio_table": [
                {"radio": "ng", "name": "ra0", "channel": "auto", "ht": 20, "tx_power_mode": "auto"},
                {"radio": "na", "name": "rai0", "channel": "auto", "ht": 80, "tx_power_mode": "auto"},
            ],
        }

        self._gateway = {
            "_id": "gw1", "mac": "aa:bb:cc:00:00:02", "name": "Cloud Gateway Max",
            "type": "udm", "state": 1, "radio_table": [],
        }
        self.restarted = []

    async def devices(self):
        return [self._device, self._gateway]

    async def device(self, mac):
        return self._device

    async def restart_device(self, mac, soft=True):
        self.restarted.append(mac)
        return []

    async def put_device(self, device_id, payload):
        self.puts.append((device_id, payload))
        return [{"_id": device_id}]

    async def block_client(self, mac):
        self.blocked.append(mac)
        return []

    async def wlanconf(self):
        return [{"_id": "w1", "name": "Home", "enabled": True}]

    async def put_wlanconf(self, wid, payload):
        self.puts.append((wid, payload))
        return []

    async def create_backup(self, days=-1):
        self.backups += 1
        return [{"filename": "backup.unf"}]

    async def speedtest(self):
        self.speedtest_started = True
        return []

    async def speedtest_status(self):
        # First call = baseline (old run); subsequent calls = the new completed run.
        seq = getattr(self, "_st_seq", 0)
        self._st_seq = seq + 1
        if seq == 0:
            return {"rundate": 1000, "xput_download": 111, "xput_upload": 11}  # stale
        return {"rundate": 2000, "xput_download": 950, "xput_upload": 42, "latency": 15,
                "status_download": 2, "status_upload": 2}


@pytest.fixture
def agent(settings):
    a = UniFiAgent(settings)
    a._classic = FakeClassic()
    return a


async def test_set_radio_dry_run_previews_without_writing(agent):
    res = await agent.set_radio("Main Floor U6+", "5GHz", channel=44, width_mhz=40, dry_run=True)
    assert res["applied"] is False
    assert res["reason"] == "dry_run"
    assert res["predicted_change"][0]["after"] == {"channel": 44, "ht": 40}
    assert agent._classic.puts == []  # nothing written


async def test_set_radio_unconfirmed_previews(agent):
    res = await agent.set_radio("Main Floor U6+", "5GHz", channel=44)
    assert res["applied"] is False and res["reason"] == "unconfirmed"
    assert agent._classic.puts == []


async def test_set_radio_confirmed_writes_full_table(agent):
    res = await agent.set_radio("Main Floor U6+", "5GHz", channel=44, width_mhz=40, confirm=True)
    assert res["applied"] is True
    assert len(agent._classic.puts) == 1
    _, payload = agent._classic.puts[0]
    assert len(payload["radio_table"]) == 2  # full array
    na = [r for r in payload["radio_table"] if r["radio"] == "na"][0]
    assert na["channel"] == 44 and na["ht"] == 40


async def test_block_client_preview_and_confirm(agent):
    preview = await agent.block_client("aa:bb:cc:dd:ee:ff")
    assert preview["applied"] is False
    assert agent._classic.blocked == []
    applied = await agent.block_client("aa:bb:cc:dd:ee:ff", confirm=True)
    assert applied["applied"] is True
    assert agent._classic.blocked == ["aa:bb:cc:dd:ee:ff"]


async def test_read_only_refuses_mutation(readonly_settings):
    a = UniFiAgent(readonly_settings)
    a._classic = FakeClassic()
    with pytest.raises(ReadOnlyError):
        await a.set_radio("Main Floor U6+", "5GHz", channel=44, confirm=True)


async def test_wlan_toggle_exceeds_default_ceiling(agent):
    # default ceiling is DEVICE; toggle_wlan is WLAN_GROUP
    with pytest.raises(BlastRadiusError):
        await agent.toggle_wlan("Home", False, confirm=True)


async def test_wlan_toggle_with_override_and_backup(settings):
    settings.max_blast_radius = BlastRadius.SITE
    settings.backup_before_risky = True
    a = UniFiAgent(settings)
    a._classic = FakeClassic()
    res = await a.toggle_wlan("Home", False, confirm=True)
    assert res["applied"] is True
    assert res["snapshot"] is True  # pre-change backup taken
    assert a._classic.backups == 1


async def test_set_radio_couples_tx_power_with_custom_mode(agent):
    res = await agent.set_radio("Main Floor U6+", "5GHz", tx_power=20, confirm=True)
    assert res["applied"] is True
    _, payload = agent._classic.puts[0]
    na = [r for r in payload["radio_table"] if r["radio"] == "na"][0]
    assert na["tx_power"] == 20
    assert na["tx_power_mode"] == "custom"  # auto-coupled


async def test_run_speedtest_waits_for_new_rundate(agent, monkeypatch):
    import asyncio as _asyncio
    monkeypatch.setattr(_asyncio, "sleep", lambda *_a, **_k: _noop())
    res = await agent.run_speedtest(confirm=True, timeout_s=30)
    assert res["applied"] is True
    # Must return the NEW run (950), not the stale baseline (111).
    assert res["result"]["download_mbps"] == 950
    assert res["result"]["rundate"] == 2000


async def _noop():
    return None


async def test_restart_gateway_is_gateway_blast_radius(agent):
    # Default ceiling is DEVICE; rebooting the gateway must be classified GATEWAY and refused.
    with pytest.raises(BlastRadiusError):
        await agent.restart_device("Cloud Gateway Max", confirm=True)


async def test_restart_ap_is_device_and_allowed(agent):
    res = await agent.restart_device("Main Floor U6+", confirm=True)
    assert res["applied"] is True
    assert agent._classic.restarted == ["aa:bb:cc:00:00:01"]


async def test_restart_gateway_override_warns_about_wan(settings):
    settings.max_blast_radius = BlastRadius.GATEWAY
    a = UniFiAgent(settings)
    a._classic = FakeClassic()
    res = await a.restart_device("Cloud Gateway Max", confirm=True)
    assert res["applied"] is True
    assert any("WAN" in w or "session" in w for w in res["warnings"])


async def test_create_backup_respects_read_only(readonly_settings):
    a = UniFiAgent(readonly_settings)
    a._classic = FakeClassic()
    with pytest.raises(ReadOnlyError):
        await a.create_backup()
    assert a._classic.backups == 0


async def test_capabilities_reports_both_apis(agent):
    caps = await agent.capabilities()
    assert caps["integration_api"] is True and caps["classic_api"] is True
    assert caps["max_blast_radius"] == "device"


async def test_required_backup_failure_prevents_wlan_change(settings):
    from unittest.mock import AsyncMock

    from unifi_agent.errors import UniFiAgentError

    settings.max_blast_radius = BlastRadius.SITE
    settings.backup_before_risky = True
    a = UniFiAgent(settings)
    a._classic = FakeClassic()
    a._classic.create_backup = AsyncMock(side_effect=RuntimeError('backup failed'))
    with pytest.raises(UniFiAgentError, match='backup failed'):
        await a.toggle_wlan('Home', False, confirm=True)
    assert a._classic.puts == []


async def test_unknown_restart_target_is_refused(agent):
    from unifi_agent.errors import UniFiAgentError

    with pytest.raises(UniFiAgentError, match='known device'):
        await agent.restart_device('ff:ff:ff:ff:ff:ff', confirm=True)
    assert agent._classic.restarted == []


async def test_speedtest_does_not_accept_incomplete_upload(agent, monkeypatch):
    import asyncio as _asyncio
    from unittest.mock import AsyncMock

    monkeypatch.setattr(_asyncio, 'sleep', lambda *_a, **_k: _noop())
    agent._classic.speedtest_status = AsyncMock(side_effect=[
        {'rundate': 1},
        {'rundate': 2, 'xput_download': 793, 'xput_upload': 0,
         'status_download': 2, 'status_upload': 1},
        {'rundate': 2, 'xput_download': 793, 'xput_upload': 15,
         'status_download': 2, 'status_upload': 2},
    ])
    result = await agent.run_speedtest(confirm=True, timeout_s=9)
    assert result['result']['upload_mbps'] == 15
    assert agent._classic.speedtest_status.call_count == 3


def test_plaintext_host_rejected(settings):
    from unifi_agent.errors import ConfigError

    settings.host = 'http://192.168.1.1'
    with pytest.raises(ConfigError, match='HTTPS'):
        _ = settings.base_url
