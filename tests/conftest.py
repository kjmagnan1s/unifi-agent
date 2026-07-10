from __future__ import annotations

from pathlib import Path

import pytest

from unifi_agent.config import Settings
from unifi_agent.safety import BlastRadius


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        host="10.0.0.1",
        site="default",
        config_dir=tmp_path,
        tls_mode="insecure",
        api_key="test-key",
        username="svc",
        password="pw",
        read_only=False,
        max_blast_radius=BlastRadius.DEVICE,
        backup_before_risky=False,
    )


@pytest.fixture
def readonly_settings(settings: Settings) -> Settings:
    settings.read_only = True
    return settings
