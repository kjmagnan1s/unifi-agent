from __future__ import annotations

import httpx
import pytest
import respx

from unifi_agent.api import ClassicClient, IntegrationClient
from unifi_agent.errors import UniFiAPIError
from unifi_agent.transport import Transport

BASE = "https://10.0.0.1"


@pytest.fixture
async def transport(settings):
    t = Transport(settings)
    await t.start()
    yield t
    await t.aclose()


def ok(data):
    return {"meta": {"rc": "ok"}, "data": data}


@respx.mock
async def test_classic_login_and_read(transport):
    respx.post(f"{BASE}/api/auth/login").mock(
        return_value=httpx.Response(200, json=ok([]), headers={"x-csrf-token": "TOK1"})
    )
    respx.get(f"{BASE}/proxy/network/api/s/default/stat/health").mock(
        return_value=httpx.Response(200, json=ok([{"subsystem": "wlan", "status": "ok"}]))
    )
    client = ClassicClient(transport.settings, transport)
    rows = await client.health()
    assert rows[0]["subsystem"] == "wlan"


@respx.mock
async def test_classic_mutation_sends_csrf(transport):
    respx.post(f"{BASE}/api/auth/login").mock(
        return_value=httpx.Response(200, json=ok([]), headers={"x-csrf-token": "CSRF-XYZ"})
    )
    route = respx.post(f"{BASE}/proxy/network/api/s/default/cmd/stamgr").mock(
        return_value=httpx.Response(200, json=ok([]))
    )
    client = ClassicClient(transport.settings, transport)
    await client.block_client("aa:bb:cc:dd:ee:ff")
    sent = route.calls.last.request
    assert sent.headers.get("x-csrf-token") == "CSRF-XYZ"
    assert b"block-sta" in sent.content


@respx.mock
async def test_classic_relogin_on_login_required(transport):
    login = respx.post(f"{BASE}/api/auth/login").mock(
        return_value=httpx.Response(200, json=ok([]), headers={"x-csrf-token": "T"})
    )
    url = f"{BASE}/proxy/network/api/s/default/stat/device"
    responses = [
        httpx.Response(401, json={"meta": {"rc": "error", "msg": "api.err.LoginRequired"}}),
        httpx.Response(200, json=ok([{"_id": "1", "mac": "aa"}])),
    ]
    respx.get(url).mock(side_effect=responses)
    client = ClassicClient(transport.settings, transport)
    rows = await client.devices()
    assert rows[0]["mac"] == "aa"
    assert login.call_count == 2  # initial + re-login


@respx.mock
async def test_classic_error_envelope_raises(transport):
    respx.post(f"{BASE}/api/auth/login").mock(
        return_value=httpx.Response(200, json=ok([]), headers={"x-csrf-token": "T"})
    )
    respx.put(f"{BASE}/proxy/network/api/s/default/rest/device/xyz").mock(
        return_value=httpx.Response(400, json={"meta": {"rc": "error", "msg": "api.err.Invalid"}})
    )
    client = ClassicClient(transport.settings, transport)
    with pytest.raises(UniFiAPIError) as exc:
        await client.put_device("xyz", {"radio_table": []})
    assert exc.value.code == "api.err.Invalid"


@respx.mock
async def test_integration_sends_api_key_and_paginates(transport):
    page1 = [{"id": str(i)} for i in range(200)]
    page2 = [{"id": "200"}]
    route = respx.get(f"{BASE}/proxy/network/integration/v1/sites/S/devices")
    route.mock(side_effect=[
        httpx.Response(200, json={"data": page1, "count": 200, "totalCount": 201}),
        httpx.Response(200, json={"data": page2, "count": 1, "totalCount": 201}),
    ])
    client = IntegrationClient(transport.settings, transport)
    devices = await client.devices("S")
    assert len(devices) == 201
    assert route.calls[0].request.headers.get("x-api-key") == "test-key"


@respx.mock
async def test_events_returns_empty_on_404_but_raises_otherwise(transport):
    respx.post(f"{BASE}/api/auth/login").mock(
        return_value=httpx.Response(200, json=ok([]), headers={"x-csrf-token": "T"})
    )
    ev = respx.get(url__regex=rf"{BASE}/proxy/network/api/s/default/stat/event.*")
    ev.mock(return_value=httpx.Response(404, text="<html/>"))
    client = ClassicClient(transport.settings, transport)
    assert await client.events() == []  # 404 -> empty, not an error

    ev.mock(return_value=httpx.Response(500, json={"meta": {"rc": "error", "msg": "boom"}}))
    with pytest.raises(UniFiAPIError):
        await client.events()  # non-404 propagates


@respx.mock
async def test_alarms_falls_back_to_list_alarm_on_404(transport):
    respx.post(f"{BASE}/api/auth/login").mock(
        return_value=httpx.Response(200, json=ok([]), headers={"x-csrf-token": "T"})
    )
    respx.get(url__regex=rf"{BASE}/proxy/network/api/s/default/stat/alarm.*").mock(
        return_value=httpx.Response(404, text="nope")
    )
    fallback = respx.get(f"{BASE}/proxy/network/api/s/default/list/alarm").mock(
        return_value=httpx.Response(200, json=ok([{"key": "EVT_x"}]))
    )
    client = ClassicClient(transport.settings, transport)
    rows = await client.alarms()
    assert rows[0]["key"] == "EVT_x"
    assert fallback.called


@respx.mock
async def test_download_backup_uses_proxy_network_prefix(transport):
    respx.post(f"{BASE}/api/auth/login").mock(
        return_value=httpx.Response(200, json=ok([]), headers={"x-csrf-token": "T"})
    )
    fn = "autobackup_10.0.162_20260101.unf"
    route = respx.get(f"{BASE}/proxy/network/dl/autobackup/{fn}").mock(
        return_value=httpx.Response(200, content=b"UNFDATA")
    )
    client = ClassicClient(transport.settings, transport)
    data = await client.download_backup(fn)
    assert data == b"UNFDATA"
    assert route.called


@respx.mock
async def test_integration_info(transport):
    respx.get(f"{BASE}/proxy/network/integration/v1/info").mock(
        return_value=httpx.Response(200, json={"applicationVersion": "10.4.57"})
    )
    client = IntegrationClient(transport.settings, transport)
    info = await client.info()
    assert info["applicationVersion"] == "10.4.57"
