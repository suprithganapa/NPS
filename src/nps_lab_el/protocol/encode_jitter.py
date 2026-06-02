from __future__ import annotations

from nps_lab_el.protocol.fec import bits_to_symbols, rs_encode, symbols_to_bits


def encode_jitter_sequence(
    token_bits: list[int],
    t0_ms: int = 1000,
    delta_ms: int = 50,
) -> list[float]:
    t0 = t0_ms / 1000.0
    t1 = (t0_ms + delta_ms) / 1000.0
    return [t1 if b else t0 for b in token_bits]


def encode_with_fec(
    token_bits: list[int],
    n: int = 32,
    k: int = 28,
    t0_ms: int = 1000,
    delta_ms: int = 50,
) -> list[float]:
    symbols = bits_to_symbols(token_bits)
    encoded_symbols = rs_encode(symbols, n, k)
    encoded_bits = symbols_to_bits(encoded_symbols)
    return encode_jitter_sequence(encoded_bits, t0_ms, delta_ms)
