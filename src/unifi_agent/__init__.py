"""unifi-agent: safety-first agentic command and control for UniFi networks.

Public surface:
    from unifi_agent import UniFiAgent, load_settings

Everything else is an implementation detail and may change between minor versions.
"""

from .config import Settings, load_settings
from .errors import (
    AuthError,
    BlastRadiusError,
    ConfirmationRequired,
    ReadOnlyError,
    TLSPinError,
    UniFiAgentError,
    UniFiAPIError,
)
from .facade import UniFiAgent

__all__ = [
    "UniFiAgent",
    "Settings",
    "load_settings",
    "UniFiAgentError",
    "UniFiAPIError",
    "AuthError",
    "TLSPinError",
    "ReadOnlyError",
    "ConfirmationRequired",
    "BlastRadiusError",
]

__version__ = "0.1.0"
