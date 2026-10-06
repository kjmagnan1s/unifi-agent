"""Private SQLite snapshots and an append-only experiment journal."""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .errors import UniFiAgentError
from .secrets import redact


def now() -> str:
    return datetime.now(UTC).isoformat()


def default_history_path() -> Path:
    root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
    return root / "unifi-agent/history.sqlite3"


class History:
    def __init__(self, path: Path | None = None, *, read_only: bool = False):
        self.path = path or default_history_path()
        if read_only:
            self.db = sqlite3.connect(self.path.resolve().as_uri() + "?mode=ro", uri=True)
            self.db.row_factory = sqlite3.Row
            return
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Create with private permissions before SQLite can write anything.
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        self.path.chmod(0o600)
        self.db = sqlite3.connect(self.path, timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT NOT NULL,
                host TEXT NOT NULL, site TEXT NOT NULL, status TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS scan_time ON scans(started_at);
            CREATE TABLE IF NOT EXISTS experiments (
                id TEXT PRIMARY KEY, created_at TEXT NOT NULL,
                baseline_id TEXT NOT NULL REFERENCES scans(id),
                kind TEXT NOT NULL, reason TEXT NOT NULL, plan TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS experiment_events (
                id INTEGER PRIMARY KEY, experiment_id TEXT NOT NULL REFERENCES experiments(id),
                at TEXT NOT NULL, status TEXT NOT NULL, payload TEXT NOT NULL
            );
            PRAGMA user_version=1;
        """)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.db.close()

    @contextmanager
    def maintenance_lock(self):
        import fcntl

        fd = os.open(str(self.path) + ".maintenance.lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)

    def save(self, scan: dict[str, Any]) -> str:
        with self.db:
            self.db.execute(
                "INSERT INTO scans VALUES (?,?,?,?,?,?,?)",
                (
                    scan["id"],
                    scan["started_at"],
                    scan["finished_at"],
                    scan["host"],
                    scan["site"],
                    scan["status"],
                    json.dumps(redact(scan), allow_nan=False),
                ),
            )
        return scan["id"]

    def get(self, scan_id: str) -> dict:
        row = self.db.execute("SELECT payload FROM scans WHERE id=?", (scan_id,)).fetchone()
        if row is None:
            raise UniFiAgentError(f"Unknown scan {scan_id}")
        return json.loads(row[0])

    def latest(self, host: str, site: str) -> dict | None:
        row = self.db.execute(
            "SELECT payload FROM scans WHERE host=? AND site=? ORDER BY started_at DESC LIMIT 1",
            (host, site),
        ).fetchone()
        return json.loads(row[0]) if row else None

    def list(self, limit: int = 12) -> list[dict]:
        return [
            dict(row)
            for row in self.db.execute(
                "SELECT id,started_at,finished_at,host,site,status FROM scans "
                "ORDER BY started_at DESC LIMIT ?",
                (limit,),
            )
        ]

    def experiment(self, baseline_id: str, kind: str, reason: str, plan: dict) -> str:
        identifier = str(uuid.uuid4())
        with self.db:
            self.db.execute(
                "INSERT INTO experiments VALUES (?,?,?,?,?,?)",
                (
                    identifier,
                    now(),
                    baseline_id,
                    kind,
                    reason,
                    json.dumps(redact(plan)),
                ),
            )
        self.event(identifier, "planned", {})
        return identifier

    def event(self, experiment_id: str, status: str, payload: dict) -> None:
        with self.db:
            self.db.execute(
                "INSERT INTO experiment_events(experiment_id,at,status,payload) VALUES (?,?,?,?)",
                (experiment_id, now(), status, json.dumps(redact(payload))),
            )

    def experiments(self) -> list[dict]:
        result = []
        for row in self.db.execute("SELECT * FROM experiments ORDER BY created_at DESC LIMIT 50"):
            entry = dict(row)
            entry["plan"] = json.loads(entry["plan"])
            entry["events"] = [
                {**dict(e), "payload": json.loads(e["payload"])}
                for e in self.db.execute(
                    "SELECT * FROM experiment_events WHERE experiment_id=? ORDER BY id",
                    (entry["id"],),
                )
            ]
            result.append(entry)
        return result

    def experiment_entry(self, experiment_id: str) -> dict:
        entry = next((e for e in self.experiments() if e["id"] == experiment_id), None)
        if entry is None:
            raise UniFiAgentError(f"Unknown experiment {experiment_id}")
        return entry


def counter_delta(before: dict, after: dict, elapsed_s: float, key: str) -> dict:
    """Reject reset/ambiguous counters, including reconnects between weekly scans."""
    a, b = before.get(key), after.get(key)
    old_up, new_up = before.get("uptime_s"), after.get("uptime_s")
    if not all(isinstance(v, (int, float)) for v in (a, b, old_up, new_up)):
        return {"value": None, "reason": "missing_counter_or_uptime"}
    # New uptime must span the full interval since the previous observation.
    if elapsed_s <= 0 or new_up < old_up or new_up + 120 < old_up + elapsed_s or b < a:
        return {"value": None, "reason": "counter_reset_or_session_changed"}
    return {"value": b - a, "interval_s": elapsed_s}


def compare(previous: dict | None, current: dict) -> dict:
    if not previous:
        return {"baseline": True, "note": "First saved scan; no trend yet."}
    if (previous["host"], previous["site"]) != (current["host"], current["site"]):
        raise ValueError("Cannot compare different networks")
    if not previous.get("samples") or not current.get("samples"):
        return {"previous_id": previous["id"], "status": "missing_samples"}
    old, new = previous["samples"][-1], current["samples"][-1]
    seconds = (
        datetime.fromisoformat(new["at"]) - datetime.fromisoformat(old["at"])
    ).total_seconds()
    a = {c["mac"]: c for c in old.get("clients", []) if c.get("mac")}
    b = {c["mac"]: c for c in new.get("clients", []) if c.get("mac")}
    observed = all(s.get("collection", {}).get("clients") == "ok" for s in (old, new))
    usage = (
        {
            mac: {k: counter_delta(a[mac], b[mac], seconds, k) for k in ("rx_bytes", "tx_bytes")}
            for mac in a.keys() & b.keys()
        }
        if observed
        else {}
    )
    return {
        "previous_id": previous["id"],
        "interval_s": seconds,
        "newly_observed_clients": sorted(b.keys() - a.keys()) if observed else None,
        "not_observed_now": sorted(a.keys() - b.keys()) if observed else None,
        "client_counter_deltas": usage,
        "note": "Not observed does not mean offline. Weekly counter differences are incomplete "
        "usage, not a full weekly billing total or continuous uptime measurement.",
    }
