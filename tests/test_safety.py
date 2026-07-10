from __future__ import annotations

import json
from pathlib import Path

import pytest

from unifi_agent.errors import BlastRadiusError, ReadOnlyError
from unifi_agent.safety import AuditLog, BlastRadius, Operation, SafetyGuard


def make_guard(tmp_path: Path, *, read_only=False, ceiling=BlastRadius.DEVICE) -> SafetyGuard:
    return SafetyGuard(
        read_only=read_only,
        max_blast_radius=ceiling,
        audit=AuditLog(tmp_path / "audit"),
    )


CLIENT_OP = Operation("block_client", BlastRadius.CLIENT)
WLAN_OP = Operation("toggle_wlan", BlastRadius.WLAN_GROUP, provisions=True)
GATEWAY_OP = Operation("wan_change", BlastRadius.GATEWAY)


def test_dry_run_never_applies(tmp_path):
    guard = make_guard(tmp_path)
    d = guard.evaluate(CLIENT_OP, confirm=True, dry_run=True)
    assert d.allowed is False
    assert d.reason == "dry_run"


def test_unconfirmed_is_preview(tmp_path):
    guard = make_guard(tmp_path)
    d = guard.evaluate(CLIENT_OP, confirm=False, dry_run=False)
    assert d.allowed is False
    assert d.reason == "unconfirmed"


def test_confirmed_proceeds(tmp_path):
    guard = make_guard(tmp_path)
    d = guard.evaluate(CLIENT_OP, confirm=True, dry_run=False)
    assert d.allowed is True
    assert d.reason == "confirmed"


def test_read_only_blocks_real_write(tmp_path):
    guard = make_guard(tmp_path, read_only=True)
    with pytest.raises(ReadOnlyError):
        guard.evaluate(CLIENT_OP, confirm=True, dry_run=False)


def test_read_only_still_allows_dry_run(tmp_path):
    guard = make_guard(tmp_path, read_only=True)
    d = guard.evaluate(CLIENT_OP, confirm=True, dry_run=True)
    assert d.allowed is False and d.reason == "dry_run"


def test_blast_radius_ceiling_refuses(tmp_path):
    guard = make_guard(tmp_path, ceiling=BlastRadius.DEVICE)
    with pytest.raises(BlastRadiusError):
        guard.evaluate(WLAN_OP, confirm=True, dry_run=False)


def test_blast_radius_override(tmp_path):
    guard = make_guard(tmp_path, ceiling=BlastRadius.DEVICE)
    d = guard.evaluate(WLAN_OP, confirm=True, dry_run=False, override_blast_radius=True)
    assert d.allowed is True


def test_blast_radius_ceiling_applies_even_to_dry_run(tmp_path):
    """A dry run above the ceiling should still refuse, so previews never imply feasibility."""
    guard = make_guard(tmp_path, ceiling=BlastRadius.DEVICE)
    with pytest.raises(BlastRadiusError):
        guard.evaluate(WLAN_OP, confirm=False, dry_run=True)


def test_provisions_and_gateway_warnings(tmp_path):
    guard = make_guard(tmp_path, ceiling=BlastRadius.GATEWAY)
    d = guard.evaluate(WLAN_OP, confirm=True, dry_run=True)
    assert any("drop" in w for w in d.warnings)
    d2 = guard.evaluate(GATEWAY_OP, confirm=True, dry_run=True)
    assert any("WAN" in w or "session" in w for w in d2.warnings)


def test_audit_log_records_and_redacts(tmp_path):
    guard = make_guard(tmp_path)
    guard.evaluate(CLIENT_OP, confirm=True, dry_run=False,
                   details={"password": "hunter2", "mac": "aa:bb"})
    files = list((tmp_path / "audit").glob("audit-*.jsonl"))
    assert files, "audit file written"
    lines = [json.loads(x) for x in files[0].read_text().splitlines()]
    allowed = [x for x in lines if x["event"] == "mutation.allowed"]
    assert allowed
    assert allowed[0]["details"]["password"] == "***REDACTED***"
    assert allowed[0]["details"]["mac"] == "aa:bb"


def test_audit_records_refusals(tmp_path):
    guard = make_guard(tmp_path, read_only=True)
    with pytest.raises(ReadOnlyError):
        guard.evaluate(CLIENT_OP, confirm=True, dry_run=False)
    files = list((tmp_path / "audit").glob("audit-*.jsonl"))
    lines = [json.loads(x) for x in files[0].read_text().splitlines()]
    assert any(x["event"] == "mutation.refused" for x in lines)


def test_blast_radius_parse_roundtrip():
    for r in BlastRadius:
        assert BlastRadius.parse(r.label) is r
    with pytest.raises(ValueError):
        BlastRadius.parse("planetary")
