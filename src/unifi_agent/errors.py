"""Exception hierarchy for unifi-agent.

All errors raised by the library derive from :class:`UniFiAgentError`, so callers
can catch the whole surface with one ``except``. Safety refusals
(:class:`ReadOnlyError`, :class:`ConfirmationRequired`, :class:`BlastRadiusError`)
are deliberately *not* subclasses of :class:`UniFiAPIError`: they are raised before
any request leaves the machine, and callers usually want to treat them differently
from a real API failure.
"""

from __future__ import annotations


class UniFiAgentError(Exception):
    """Base class for every error this library raises."""


class ConfigError(UniFiAgentError):
    """Configuration is missing or invalid (e.g. no host, no credentials)."""


class TLSPinError(UniFiAgentError):
    """The gateway presented a certificate that does not match the pinned one.

    This is a hard security stop: either the certificate legitimately rotated
    (firmware update / custom cert) and you must re-pin, or something is
    intercepting the connection.
    """


class AuthError(UniFiAgentError):
    """Authentication failed or no usable credential is configured for the request."""


class UniFiAPIError(UniFiAgentError):
    """The gateway returned an error response.

    Attributes:
        status: HTTP status code.
        code: Machine-readable error code (``meta.msg`` for classic API,
            ``code`` for the Integration API), if any.
        message: Human-readable message extracted from the body.
        path: Request path that failed.
    """

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        code: str | None = None,
        path: str | None = None,
    ) -> None:
        self.status = status
        self.code = code
        self.message = message
        self.path = path
        detail = message
        if status is not None:
            detail = f"[{status}] {detail}"
        if code:
            detail = f"{detail} ({code})"
        if path:
            detail = f"{detail} <{path}>"
        super().__init__(detail)


class RateLimitError(UniFiAPIError):
    """The gateway rate-limited the request (HTTP 429). Back off and retry."""

    def __init__(self, message: str, *, retry_after: float | None = None, **kw: object) -> None:
        self.retry_after = retry_after
        super().__init__(message, **kw)  # type: ignore[arg-type]


# --- Safety refusals (raised locally, before any network I/O) -----------------


class SafetyRefusal(UniFiAgentError):
    """Base class for local safety refusals — the request was never sent."""


class ReadOnlyError(SafetyRefusal):
    """A mutation was attempted while the agent is in read-only mode."""


class ConfirmationRequired(SafetyRefusal):
    """A mutation requires explicit confirmation that was not provided.

    Attributes:
        operation: Name of the operation.
        preview: The predicted change set (what a dry-run produced).
    """

    def __init__(self, operation: str, preview: object = None) -> None:
        self.operation = operation
        self.preview = preview
        super().__init__(
            f"Operation '{operation}' requires confirm=True. "
            f"Run with dry_run=True first to preview the change."
        )


class BlastRadiusError(SafetyRefusal):
    """A mutation's blast radius exceeds the configured maximum."""

    def __init__(self, operation: str, radius: str, maximum: str) -> None:
        self.operation = operation
        self.radius = radius
        self.maximum = maximum
        super().__init__(
            f"Operation '{operation}' has blast radius '{radius}', which exceeds the "
            f"configured maximum '{maximum}'. Raise UNIFI_MAX_BLAST_RADIUS or pass "
            f"override_blast_radius=True to proceed."
        )
