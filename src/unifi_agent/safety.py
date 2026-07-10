"""The safety layer: blast-radius classification, mutation guards, and audit log.

Every mutation in this project flows through :class:`SafetyGuard`. The guard enforces,
in order:

1. **Read-only mode** — if enabled, no mutation is ever sent.
2. **Blast radius ceiling** — mutations classified above the configured maximum are
   refused unless explicitly overridden.
3. **Confirmation** — mutations require ``confirm=True``; without it the guard returns
   a dry-run preview instead of acting.

Independently, :class:`AuditLog` records every attempt (dry-run and real, allowed and
refused) as an append-only JSONL line with secrets redacted. The audit trail is the
project's own record; UniFi's Activity Log / syslog is the independent one.
"""

from __future__ import annotations

import contextlib
import enum
import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .errors import BlastRadiusError, ConfirmationRequired, ReadOnlyError
from .secrets import redact


class BlastRadius(enum.IntEnum):
    """How far the effect of a mutation reaches, ordered from smallest to largest.

    The ordering is what the ceiling check compares against, so the integer values
    matter: a higher value is a bigger blast.
    """

    NONE = 0  # no service impact (e.g. create backup, set client name)
    CLIENT = 1  # affects a single client (block/kick/authorize)
    DEVICE = 2  # restarts/disrupts one device and anything downstream of it
    WLAN_GROUP = 3  # reprovisions every AP broadcasting a WLAN group
    SITE = 4  # reprovisions the whole site
    GATEWAY = 5  # can drop the WAN / the management session itself

    @classmethod
    def parse(cls, name: str) -> BlastRadius:
        try:
            return cls[name.strip().upper()]
        except KeyError as exc:
            valid = ", ".join(r.name.lower() for r in cls)
            raise ValueError(f"unknown blast radius {name!r}; valid: {valid}") from exc

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Operation:
    """Metadata describing a mutation, used for guarding and audit."""

    name: str
    blast_radius: BlastRadius
    # Human-readable note about what this disrupts, surfaced in previews/warnings.
    disruption: str = ""
    # True if this op reprovisions devices (triggers the ~30-60s client-drop cycle).
    provisions: bool = False


@dataclass
class GuardDecision:
    """The result of asking the guard whether a mutation may proceed."""

    operation: str
    blast_radius: str
    allowed: bool  # True = proceed with the real call; False = this is a dry-run/preview
    dry_run: bool
    reason: str
    disruption: str = ""
    warnings: list[str] = field(default_factory=list)


class AuditLog:
    """Append-only JSONL audit log. One file per UTC day. Secrets are redacted."""

    def __init__(self, directory: Path, *, enabled: bool = True) -> None:
        self.directory = directory
        self.enabled = enabled
        if enabled:
            directory.mkdir(parents=True, exist_ok=True)
            with contextlib.suppress(OSError):
                os.chmod(directory, 0o700)

    def _path(self, when: datetime) -> Path:
        return self.directory / f"audit-{when:%Y%m%d}.jsonl"

    def record(self, event: str, payload: dict[str, Any]) -> None:
        if not self.enabled:
            return
        now = datetime.now(UTC)
        line = {
            "ts": now.isoformat(),
            "event": event,
            **{k: redact(v) for k, v in payload.items()},
        }
        path = self._path(now)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(line, default=str) + "\n")
        with contextlib.suppress(OSError):
            os.chmod(path, 0o600)


class SafetyGuard:
    """Enforces read-only mode, blast-radius ceiling, and confirmation on mutations."""

    def __init__(
        self,
        *,
        read_only: bool,
        max_blast_radius: BlastRadius,
        audit: AuditLog,
    ) -> None:
        self.read_only = read_only
        self.max_blast_radius = max_blast_radius
        self.audit = audit

    def evaluate(
        self,
        operation: Operation,
        *,
        confirm: bool,
        dry_run: bool,
        override_blast_radius: bool = False,
        details: dict[str, Any] | None = None,
    ) -> GuardDecision:
        """Decide whether ``operation`` may proceed, and record the decision.

        Returns a :class:`GuardDecision`. If ``allowed`` is False the caller must NOT
        perform the real mutation; it should surface the decision as a preview.

        Raises:
            ReadOnlyError: read-only mode is on and this is a real (non-dry-run) attempt.
            BlastRadiusError: blast radius exceeds the ceiling and was not overridden.
        """
        details = details or {}
        warnings: list[str] = []
        if operation.provisions:
            warnings.append(
                "This reprovisions affected devices; wireless clients on them drop "
                "for ~30-60s."
            )
        if operation.blast_radius >= BlastRadius.GATEWAY:
            warnings.append(
                "This can interrupt the WAN and/or this management session itself."
            )

        base = {
            "operation": operation.name,
            "blast_radius": operation.blast_radius.label,
            "confirm": confirm,
            "dry_run": dry_run,
            "details": details,
        }

        # 1) Blast radius ceiling — checked even for dry runs so previews are honest.
        if operation.blast_radius > self.max_blast_radius and not override_blast_radius:
            self.audit.record("mutation.refused", {**base, "reason": "blast_radius"})
            raise BlastRadiusError(
                operation.name,
                operation.blast_radius.label,
                self.max_blast_radius.label,
            )

        # 2) Read-only mode.
        if self.read_only and not dry_run:
            self.audit.record("mutation.refused", {**base, "reason": "read_only"})
            raise ReadOnlyError(
                f"Operation '{operation.name}' is a mutation but the agent is read-only. "
                f"Set UNIFI_READ_ONLY=false to allow writes."
            )

        # 3) Dry-run or unconfirmed -> preview only.
        if dry_run or not confirm:
            reason = "dry_run" if dry_run else "unconfirmed"
            self.audit.record("mutation.preview", {**base, "reason": reason})
            return GuardDecision(
                operation=operation.name,
                blast_radius=operation.blast_radius.label,
                allowed=False,
                dry_run=dry_run,
                reason=reason,
                disruption=operation.disruption,
                warnings=warnings,
            )

        # 4) Cleared to proceed.
        self.audit.record("mutation.allowed", base)
        return GuardDecision(
            operation=operation.name,
            blast_radius=operation.blast_radius.label,
            allowed=True,
            dry_run=False,
            reason="confirmed",
            disruption=operation.disruption,
            warnings=warnings,
        )

    def require_confirmation(self, decision: GuardDecision, preview: Any) -> None:
        """Raise :class:`ConfirmationRequired` for an unconfirmed non-dry-run attempt.

        Facade methods that must return a value (rather than a preview object) call this
        to turn a soft "not allowed" into a hard stop when the caller neither confirmed
        nor asked for a dry run.
        """
        if not decision.allowed and decision.reason == "unconfirmed":
            raise ConfirmationRequired(decision.operation, preview)
