"""Secret resolution and storage.

Secrets (API key, local admin password) are resolved in priority order:

1. Process environment (e.g. ``UNIFI_API_KEY``) — best for CI / containers.
2. A ``.env`` file in the current directory or config dir — convenient, but plaintext.
3. The OS keyring (macOS Keychain, Secret Service, Windows Credential Locker) — the
   recommended store for interactive machines. Written by ``unifi-agent setup``.

The library never prints a secret. :func:`redact` is applied to everything that
reaches a log or tool output.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

KEYRING_SERVICE = "unifi-agent"

# Field names whose values must never appear in logs or tool output. Covers the classic
# UniFi ``x_*`` secret family (x_passphrase, x_authkey, x_vwirekey, x_ssh_password, ...).
_SECRET_KEY_PATTERN = re.compile(
    r"(api[_-]?key|x-api-key|password|passphrase|secret|authkey|vwirekey|"
    r"token|csrf|cookie|psk|shared[_-]?secret|radius[_-]?secret|private[_-]?key|"
    r"x_[a-z_]*(key|password|secret|pass))",
    re.IGNORECASE,
)

# Standalone secret-looking tokens embedded in free text (JWTs, hex/base64 keys). The 32+
# threshold catches classic 32-hex device keys while staying above MAC/UUID-with-dashes
# false positives (MACs use colons; UUIDs are 36 with dashes but segmented).
_INLINE_SECRET_PATTERN = re.compile(
    r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"  # JWT
    r"|[A-Fa-f0-9]{32,}"  # hex device/auth keys
    r"|[A-Za-z0-9_-]{40,})\b"  # long opaque tokens
)

REDACTED = "***REDACTED***"


def _load_dotenv(path: Path) -> dict[str, str]:
    """Parse a minimal .env file (KEY=VALUE lines). No shell expansion."""
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key:
            values[key] = val
    return values


class SecretStore:
    """Resolves and persists secrets across env, .env, and the OS keyring."""

    def __init__(self, config_dir: Path, dotenv_paths: list[Path] | None = None) -> None:
        self.config_dir = config_dir
        # SECURITY: do NOT auto-load a .env from the current working directory. A .env
        # dropped in cwd could override UNIFI_HOST/UNIFI_TLS while credentials still come
        # from the keyring, silently redirecting secrets to an attacker's host with TLS
        # off. Only the config-dir .env is trusted by default; opt into another location
        # explicitly via UNIFI_ENV_FILE (wired in config.load_settings).
        paths = dotenv_paths or [config_dir / ".env"]
        self._dotenv: dict[str, str] = {}
        for p in reversed(paths):  # later paths are lower priority
            self._dotenv.update(_load_dotenv(p))

    def get(self, env_key: str, *, keyring_key: str | None = None) -> str | None:
        """Return a secret/setting by its environment variable name, or None."""
        if env_key in os.environ and os.environ[env_key] != "":
            return os.environ[env_key]
        if env_key in self._dotenv and self._dotenv[env_key] != "":
            return self._dotenv[env_key]
        return self._keyring_get(keyring_key or env_key)

    @staticmethod
    def _keyring_get(key: str) -> str | None:
        try:
            import keyring
        except Exception:
            return None
        try:
            return keyring.get_password(KEYRING_SERVICE, key)
        except Exception:
            return None

    @staticmethod
    def set(key: str, value: str) -> None:
        """Store a secret in the OS keyring. Raises if no backend is available."""
        import keyring

        keyring.set_password(KEYRING_SERVICE, key, value)

    @staticmethod
    def delete(key: str) -> None:
        try:
            import keyring

            keyring.delete_password(KEYRING_SERVICE, key)
        except Exception:
            pass


def redact(value: object) -> object:
    """Recursively redact secret-looking fields and inline secrets.

    - dict keys matching secret patterns have their values replaced
    - strings that look like JWTs or long opaque tokens are masked
    - lists/tuples are processed element-wise
    Everything else is returned unchanged. Safe to call on arbitrary JSON.
    """
    if isinstance(value, dict):
        out: dict[object, object] = {}
        for k, v in value.items():
            if isinstance(k, str) and _SECRET_KEY_PATTERN.search(k):
                out[k] = REDACTED
            else:
                out[k] = redact(v)
        return out
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return _INLINE_SECRET_PATTERN.sub(REDACTED, value)
    return value
