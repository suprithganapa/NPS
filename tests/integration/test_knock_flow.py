import hashlib
import hmac

import pytest

from nps_lab_el.crypto.totp import get_counter
from nps_lab_el.models.auth import AuthorizationState, AuthToken, CaptureEvent
from nps_lab_el.protocol.encode_jitter import encode_with_fec
from nps_lab_el.services.auth_engine import AuthEngine


def _make_valid_token(totp_secret: str, window_seconds: int = 60) -> AuthToken:
    payload = b"\x42" * 16
    counter = get_counter(window_seconds)
    channel_mask = 0x01
    mac_input = payload + counter.to_bytes(8, "big") + channel_mask.to_bytes(1, "big")
    mac = hmac.new(totp_secret.encode(), mac_input, hashlib.sha256).digest()[:16]
    return AuthToken(
        payload=payload,
        totp_counter=counter,
        channel_mask=channel_mask,
        mac=mac,
    )


def _token_to_events(token: AuthToken, src: str = "10.0.0.1") -> list[CaptureEvent]:
    bits = token.to_bits()
    iats = encode_with_fec(bits, n=32, k=28, t0_ms=1000, delta_ms=50)
    events = []
    t = 1000.0
    events.append(CaptureEvent(
        ts=t, src=src, dst="10.0.0.2",
        icmp_id=0, icmp_seq=0, ip_id=0, ttl=64, tos=0, icmp_type=8,
    ))
    for iat in iats:
        t += iat
        events.append(CaptureEvent(
            ts=t, src=src, dst="10.0.0.2",
            icmp_id=0, icmp_seq=0, ip_id=0, ttl=64, tos=0, icmp_type=8,
        ))
    return events


@pytest.mark.simulation
class TestKnockFlow:
    def test_end_to_end_authorization(self, test_config):
        token = _make_valid_token(test_config.auth.totp_secret, test_config.auth.window_seconds)
        events = _token_to_events(token)
        engine = AuthEngine(test_config)
        session = engine.process_events(events)
        assert session.state == AuthorizationState.AUTHORIZED

    def test_replay_rejected(self, test_config):
        token = _make_valid_token(test_config.auth.totp_secret, test_config.auth.window_seconds)
        events = _token_to_events(token)
        engine = AuthEngine(test_config)
        session1 = engine.process_events(events)
        assert session1.state == AuthorizationState.AUTHORIZED
        # Replay same events
        session2 = engine.process_events(events)
        assert session2.state == AuthorizationState.DENIED

    def test_invalid_token_denied(self, test_config):
        token = AuthToken(
            payload=b"\x00" * 16,
            totp_counter=0,
            channel_mask=0,
            mac=b"\x00" * 16,
        )
        events = _token_to_events(token)
        engine = AuthEngine(test_config)
        session = engine.process_events(events)
        assert session.state == AuthorizationState.DENIED
