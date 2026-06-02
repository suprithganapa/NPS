from __future__ import annotations

from nps_lab_el.protocol.fec import bits_to_symbols, rs_decode, symbols_to_bits


def classify_iat(
    dt: float,
    t0_ms: int = 1000,
    delta_ms: int = 50,
    tau_ms: int = 25,
) -> int | None:
    t0 = t0_ms / 1000.0
    t1 = (t0_ms + delta_ms) / 1000.0
    tau = tau_ms / 1000.0
    if abs(dt - t0) <= tau:
        return 0
    if abs(dt - t1) <= tau:
        return 1
    return None


def extract_iats(events: list) -> list[float]:
    if len(events) < 2:
        return []
    return [events[i + 1].ts - events[i].ts for i in range(len(events) - 1)]


def decode_jitter_burst(
    events: list,
    t0_ms: int = 1000,
    delta_ms: int = 50,
    tau_ms: int = 25,
    fec_n: int = 32,
    fec_k: int = 28,
    expected_bits: int = 328,
) -> list[int] | None:
    iats = extract_iats(events)
    classified = [classify_iat(dt, t0_ms, delta_ms, tau_ms) for dt in iats]
    bits = [0 if b is None else b for b in classified]
    symbols = bits_to_symbols(bits)
    decoded = rs_decode(symbols, fec_n, fec_k)
    if decoded is None:
        return None
    return symbols_to_bits(decoded, expected_bits)


def sessionize_events(events: list, gap_threshold: float = 30.0) -> list[list]:
    if not events:
        return []
    sessions: list[list] = [[events[0]]]
    for i in range(1, len(events)):
        if events[i].ts - events[i - 1].ts > gap_threshold:
            sessions.append([events[i]])
        else:
            sessions[-1].append(events[i])
    return sessions


def is_likely_knock(
    events: list,
    min_symbols: int = 160,
    t0_ms: int = 1000,
    delta_ms: int = 50,
    tau_ms: int = 25,
) -> bool:
    if len(events) < min_symbols:
        return False
    iats = extract_iats(events)
    if not iats:
        return False
    classified = [classify_iat(dt, t0_ms, delta_ms, tau_ms) for dt in iats]
    valid = sum(1 for c in classified if c is not None)
    return valid / len(classified) > 0.5
