import hashlib
import hmac

import pytest

from nps_lab_el.models.auth import AuthToken
from nps_lab_el.models.config import (
    AppConfig,
    AuthConfig,
    ChannelsConfig,
    FecConfig,
    JitterConfig,
    ServerConfig,
)


@pytest.fixture
def test_totp_secret() -> str:
    return "JBSWY3DPEHPK3PXP"


@pytest.fixture
def test_config(test_totp_secret: str) -> AppConfig:
    return AppConfig(
        server=ServerConfig(ip="127.0.0.1", iface="lo"),
        auth=AuthConfig(
            totp_secret=test_totp_secret,
            window_seconds=60,
            ttl_auth_seconds=300,
        ),
        channels=ChannelsConfig(
            jitter=JitterConfig(enabled=True, t0_ms=1000, delta_ms=50, tau_ms=25),
        ),
        fec=FecConfig(enabled=True, n=32, k=28),
    )


@pytest.fixture
def sample_auth_token(test_totp_secret: str) -> AuthToken:
    from nps_lab_el.crypto.totp import get_counter

    payload = b"\x01" * 16
    counter = get_counter(60)
    channel_mask = 0x01
    mac_input = payload + counter.to_bytes(8, "big") + channel_mask.to_bytes(1, "big")
    mac = hmac.new(test_totp_secret.encode(), mac_input, hashlib.sha256).digest()[:16]
    return AuthToken(
        payload=payload,
        totp_counter=counter,
        channel_mask=channel_mask,
        mac=mac,
    )
