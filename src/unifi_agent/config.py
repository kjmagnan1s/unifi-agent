"""Runtime configuration and secret wiring.

:class:`Settings` is the single source of truth for how the agent connects and how
strict it is. Build it with :func:`load_settings`, which layers environment variables,
an optional ``.env`` file, and the OS keyring (via :class:`~unifi_agent.secrets.SecretStore`).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .errors import ConfigError
from .safety import BlastRadius
from .secrets import SecretStore

# Keyring entry names written by `unifi-agent setup`.
KR_API_KEY = "UNIFI_API_KEY"
KR_USERNAME = "UNIFI_USERNAME"
KR_PASSWORD = "UNIFI_PASSWORD"


def default_config_dir() -> Path:
    """~/.config/unifi-agent, honoring XDG_CONFIG_HOME."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    root = Path(xdg) if xdg else Path.home() / ".config"
    return root / "unifi-agent"


def _as_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    """Immutable-ish view of everything the agent needs to run."""

    host: str
    site: str
    config_dir: Path

    # TLS mode: "pin" (trust-on-first-use, default), "system" (normal CA verification,
    # for consoles with a real cert), or "insecure" (no verification — testing only).
    tls_mode: str

    # Credentials (may be None if a given auth surface isn't configured).
    api_key: str | None
    username: str | None
    password: str | None

    # Safety
    read_only: bool
    max_blast_radius: BlastRadius
    backup_before_risky: bool

    # Networking
    request_timeout: float = 30.0
    prefer_lan: bool = True

    @property
    def base_url(self) -> str:
        host = self.host
        if "://" not in host:
            host = f"https://{host}"
        if not host.lower().startswith("https://"):
            raise ConfigError("UNIFI_HOST must use HTTPS; plaintext authentication is forbidden.")
        return host.rstrip("/")

    @property
    def pinned_cert_path(self) -> Path:
        return self.config_dir / "pinned-cert.pem"

    @property
    def audit_dir(self) -> Path:
        return self.config_dir / "audit"

    def has_integration_auth(self) -> bool:
        return bool(self.api_key)

    def has_classic_auth(self) -> bool:
        return bool(self.username and self.password)

    def require_any_auth(self) -> None:
        if not (self.has_integration_auth() or self.has_classic_auth()):
            raise ConfigError(
                "No credentials configured. Run `unifi-agent setup` to store an API key "
                "and/or a local admin login (API key covers most reads/writes; the local "
                "login is needed for radios, speedtest, events, and backups)."
            )


def load_settings(config_dir: Path | None = None) -> Settings:
    """Assemble :class:`Settings` from env, .env, and the keyring."""
    cfg_dir = config_dir or default_config_dir()
    cfg_dir.mkdir(parents=True, exist_ok=True)
    # Only the config-dir .env is trusted by default. An extra file may be opted into
    # explicitly via UNIFI_ENV_FILE (it wins over the config-dir .env but never over the
    # process environment). A stray .env in the cwd is deliberately NOT auto-loaded.
    dotenv_paths = [cfg_dir / ".env"]
    extra_env = os.environ.get("UNIFI_ENV_FILE")
    if extra_env:
        dotenv_paths.insert(0, Path(extra_env))
    store = SecretStore(cfg_dir, dotenv_paths=dotenv_paths)

    host = store.get("UNIFI_HOST") or "192.168.1.1"
    site = store.get("UNIFI_SITE") or "default"
    tls_mode = (store.get("UNIFI_TLS") or "pin").strip().lower()
    if tls_mode not in {"pin", "system", "insecure"}:
        raise ConfigError(f"UNIFI_TLS must be pin|system|insecure, got {tls_mode!r}")

    max_radius_raw = store.get("UNIFI_MAX_BLAST_RADIUS") or "device"
    try:
        max_radius = BlastRadius.parse(max_radius_raw)
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc

    return Settings(
        host=host,
        site=site,
        config_dir=cfg_dir,
        tls_mode=tls_mode,
        api_key=store.get("UNIFI_API_KEY", keyring_key=KR_API_KEY),
        username=store.get("UNIFI_USERNAME", keyring_key=KR_USERNAME),
        password=store.get("UNIFI_PASSWORD", keyring_key=KR_PASSWORD),
        read_only=_as_bool(store.get("UNIFI_READ_ONLY"), False),
        max_blast_radius=max_radius,
        backup_before_risky=_as_bool(store.get("UNIFI_BACKUP_BEFORE_RISKY"), True),
        request_timeout=_parse_timeout(store.get("UNIFI_TIMEOUT")),
    )


def _parse_timeout(raw: str | None) -> float:
    if not raw:
        return 30.0
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigError(f"UNIFI_TIMEOUT must be a number of seconds, got {raw!r}") from exc
