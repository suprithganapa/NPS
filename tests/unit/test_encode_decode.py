from dataclasses import dataclass

from nps_lab_el.protocol.decode import (
    classify_iat,
    decode_jitter_burst,
    extract_iats,
    is_likely_knock,
    sessionize_events,
)
from nps_lab_el.protocol.encode_jitter import encode_jitter_sequence, encode_with_fec


@dataclass
class FakeEvent:
    ts: float
    src: str = "10.0.0.1"
    dst: str = "10.0.0.2"
    icmp_id: int = 0
    icmp_seq: int = 0
    ip_id: int = 0
    ttl: int = 64
    tos: int = 0
    icmp_type: int = 8


class TestEncodeJitter:
    def test_encode_jitter_sequence_values(self):
        bits = [0, 1, 0, 1]
        iats = encode_jitter_sequence(bits, t0_ms=1000, delta_ms=50)
        assert len(iats) == 4
        assert iats[0] == 1.0    # bit 0 -> t0
        assert iats[1] == 1.05   # bit 1 -> t1
        assert iats[2] == 1.0
        assert iats[3] == 1.05


class TestClassifyIat:
    def test_exact_t0(self):
        assert classify_iat(1.0, t0_ms=1000, delta_ms=50, tau_ms=25) == 0

    def test_exact_t1(self):
        assert classify_iat(1.05, t0_ms=1000, delta_ms=50, tau_ms=25) == 1

    def test_out_of_range(self):
        assert classify_iat(2.0, t0_ms=1000, delta_ms=50, tau_ms=25) is None

    def test_within_tau_of_t0(self):
        assert classify_iat(1.02, t0_ms=1000, delta_ms=50, tau_ms=25) == 0

    def test_within_tau_of_t1(self):
        assert classify_iat(1.07, t0_ms=1000, delta_ms=50, tau_ms=25) == 1


class TestEncodeDecode:
    def test_encode_with_fec_roundtrip(self):
        # 28 symbols * 8 bits = 224 bits
        bits = [0] * 224
        bits[0] = 1
        bits[7] = 1
        iats = encode_with_fec(bits, n=32, k=28, t0_ms=1000, delta_ms=50)
        # Build fake events from IATs
        events = [FakeEvent(ts=0.0)]
        t = 0.0
        for iat in iats:
            t += iat
            events.append(FakeEvent(ts=t))
        decoded = decode_jitter_burst(events, t0_ms=1000, delta_ms=50, tau_ms=25, fec_n=32, fec_k=28)
        assert decoded is not None
        assert decoded[:len(bits)] == bits


class TestSessionize:
    def test_sessionize_splits_on_gap(self):
        events = [
            FakeEvent(ts=0.0),
            FakeEvent(ts=1.0),
            FakeEvent(ts=2.0),
            FakeEvent(ts=50.0),  # gap > 30
            FakeEvent(ts=51.0),
        ]
        sessions = sessionize_events(events, gap_threshold=30.0)
        assert len(sessions) == 2
        assert len(sessions[0]) == 3
        assert len(sessions[1]) == 2

    def test_sessionize_empty(self):
        assert sessionize_events([]) == []


class TestIsLikelyKnock:
    def test_too_few_events(self):
        events = [FakeEvent(ts=float(i)) for i in range(10)]
        assert is_likely_knock(events, min_symbols=160) is False

    def test_likely_knock_with_valid_iats(self):
        # Create events with IATs at t0=1.0s
        events = [FakeEvent(ts=float(i) * 1.0) for i in range(200)]
        result = is_likely_knock(events, min_symbols=160, t0_ms=1000, delta_ms=50, tau_ms=25)
        assert result is True


class TestExtractIats:
    def test_basic(self):
        events = [FakeEvent(ts=0.0), FakeEvent(ts=1.0), FakeEvent(ts=2.5)]
        iats = extract_iats(events)
        assert len(iats) == 2
        assert abs(iats[0] - 1.0) < 1e-9
        assert abs(iats[1] - 1.5) < 1e-9

    def test_single_event(self):
        assert extract_iats([FakeEvent(ts=0.0)]) == []
