from __future__ import annotations

import pytest

from unifi_agent.facade import UniFiAgent
from unifi_agent.loops import diagnostics_once


class FakeClassicForLoops:
    async def health(self):
        return [{"subsystem": "wlan", "status": "warning", "num_user": 30},
                {"subsystem": "wan", "status": "ok"}]

    async def devices(self):
        return [
            {"_id": "gw", "mac": "aa:bb:cc:00:00:02", "model": "UCGMAX", "type": "udm",
             "state": 1, "num_sta": 30, "radio_table": []},
            {"_id": "ap1", "mac": "aa:bb:cc:00:00:01", "name": "Main", "model": "UAPL6",
             "type": "uap", "state": 1, "num_sta": 7,
             "radio_table": [{"radio": "ng", "channel": 3, "ht": 20},
                             {"radio": "na", "channel": 44, "ht": 80}]},
            {"_id": "ap2", "mac": "f4:e2:c6:f8:02:d1", "name": "Second", "model": "UAPL6",
             "type": "uap", "state": 1, "num_sta": 23,
             "radio_table": [{"radio": "ng", "channel": 3, "ht": 20},
                             {"radio": "na", "channel": 149, "ht": 80}]},
            {"_id": "ap3", "mac": "80:2a:a8:49:1a:11", "name": "OldAP", "model": "U7LT",
             "type": "uap", "state": 0, "adopted": True, "num_sta": 0, "radio_table": []},
        ]

    async def clients(self):
        return [
            {"mac": "c1", "hostname": "phone", "signal": -80, "is_wired": False, "radio": "ng"},
            {"mac": "c2", "hostname": "laptop", "signal": -55, "is_wired": False, "radio": "na"},
        ]

    async def speedtest_status(self):
        return {"rundate": 1783700000, "latency": 16, "xput_download": 900, "xput_upload": 40}


@pytest.fixture
def loop_agent(settings):
    a = UniFiAgent(settings)
    a._classic = FakeClassicForLoops()
    return a


async def test_diagnostics_flags_offline_and_weak_and_cochannel(loop_agent):
    report = await diagnostics_once(loop_agent)
    findings = report["findings"]
    # offline adopted AP
    assert any("OldAP" in f["detail"] and f["area"] == "device" for f in findings)
    # wlan subsystem warning
    assert any(f["area"] == "wlan" for f in findings)
    # weak client
    assert any("weak signal" in f["detail"] for f in findings)
    # co-channel 2.4GHz recommendation (both APs on ch 3, and 3 is not 1/6/11)
    recs = report["recommendations"]
    assert any("2.4GHz" in r["detail"] for r in recs)
    assert report["summary"]["device_count"] == 4
    assert report["last_speedtest"]["download_mbps"] == 900


async def test_diagnostics_clean_network_has_no_findings(settings):
    class Clean:
        async def health(self):
            return [{"subsystem": "wlan", "status": "ok"}, {"subsystem": "wan", "status": "ok"}]

        async def devices(self):
            return [{"_id": "ap", "mac": "a", "name": "AP", "type": "uap", "state": 1,
                     "num_sta": 2, "radio_table": [{"radio": "ng", "channel": 6, "ht": 20}]}]

        async def clients(self):
            return [{"mac": "c", "signal": -50, "is_wired": False, "radio": "ng"}]

        async def speedtest_status(self):
            return {}

    a = UniFiAgent(settings)
    a._classic = Clean()
    report = await diagnostics_once(a)
    assert report["findings"] == []
