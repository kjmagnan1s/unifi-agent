from __future__ import annotations

import pytest

from unifi_agent.errors import UniFiAgentError
from unifi_agent.facade import apply_radio_change
from unifi_agent.models import normalize_client, normalize_device
from unifi_agent.secrets import redact


def _table():
    return [
        {"radio": "ng", "name": "ra0", "channel": "auto", "ht": 20, "tx_power_mode": "auto"},
        {"radio": "na", "name": "rai0", "channel": "auto", "ht": 80, "tx_power_mode": "auto"},
    ]


def test_radio_change_targets_one_band():
    new, diff = apply_radio_change(_table(), {"na"}, {"channel": 44, "ht": 40})
    assert new[0]["channel"] == "auto"  # 2.4 untouched
    assert new[1]["channel"] == 44 and new[1]["ht"] == 40
    assert len(new) == 2  # full array preserved
    assert diff[0]["after"] == {"channel": 44, "ht": 40}
    assert diff[0]["before"] == {"channel": "auto", "ht": 80}


def test_radio_change_no_op_when_same_value():
    _, diff = apply_radio_change(_table(), {"na"}, {"ht": 80})
    assert diff == []


def test_radio_change_ignores_none_values():
    new, diff = apply_radio_change(_table(), {"ng"}, {"channel": 6, "ht": None})
    assert new[0]["channel"] == 6
    assert new[0]["ht"] == 20  # unchanged (None ignored)


def test_radio_change_unknown_band_raises():
    with pytest.raises(UniFiAgentError):
        apply_radio_change(_table(), {"6e"}, {"channel": 37})


def test_normalize_device_projects_and_flags_online():
    raw = {"_id": "x", "mac": "aa", "model": "UAPL6", "type": "uap", "state": 1,
           "num_sta": 3, "radio_table": [{"radio": "na", "channel": 36, "ht": 80}]}
    nd = normalize_device(raw)
    assert nd["online"] is True and nd["clients"] == 3
    assert nd["radios"][0]["band"] == "5GHz"


def test_normalize_client_band_and_blocked():
    c = {"mac": "bb", "hostname": "phone", "radio": "ng", "blocked": True, "signal": -60}
    nc = normalize_client(c)
    assert nc["band"] == "2.4GHz" and nc["blocked"] is True and nc["signal_dbm"] == -60


def test_redact_nested_and_inline():
    payload = {
        "x_passphrase": "s3cret",
        "wlans": [{"name": "Home", "x_passphrase": "abc"}],
        "note": "token eyJraWQiOiJhIn0.eyJzdWIiOiIxIn0.QQQQQQQQQQQQQQQQQQQQ done",
        "csrf": "zzz",
    }
    r = redact(payload)
    assert r["x_passphrase"] == "***REDACTED***"
    assert r["wlans"][0]["x_passphrase"] == "***REDACTED***"
    assert r["wlans"][0]["name"] == "Home"
    assert r["csrf"] == "***REDACTED***"
    assert "***REDACTED***" in r["note"]


def test_redact_covers_device_auth_keys():
    # Raw classic device objects carry x_authkey / x_vwirekey (32-hex adoption/SSH keys).
    raw = {"mac": "aa:bb:cc:dd:ee:ff", "name": "AP", "x_authkey": "deadbeef" * 4,
           "x_vwirekey": "a" * 32, "channel": 36}
    r = redact(raw)
    assert r["x_authkey"] == "***REDACTED***"
    assert r["x_vwirekey"] == "***REDACTED***"
    assert r["mac"] == "aa:bb:cc:dd:ee:ff"  # MAC preserved (not a secret)
    assert r["name"] == "AP" and r["channel"] == 36
