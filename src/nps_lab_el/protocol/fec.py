from __future__ import annotations

import reedsolo


def rs_encode(symbols: list[int], n: int = 32, k: int = 28) -> list[int]:
    nsym = n - k
    codec = reedsolo.RSCodec(nsym)
    encoded_all: list[int] = []
    for start in range(0, len(symbols), k):
        block = symbols[start:start + k]
        if len(block) < k:
            block = block + [0] * (k - len(block))
        encoded = codec.encode(bytearray(block))
        encoded_all.extend(list(encoded)[:n])
    return encoded_all


def rs_decode(symbols: list[int], n: int = 32, k: int = 28) -> list[int] | None:
    nsym = n - k
    codec = reedsolo.RSCodec(nsym)
    decoded_all: list[int] = []
    for start in range(0, len(symbols), n):
        block = symbols[start:start + n]
        if len(block) < n:
            block = block + [0] * (n - len(block))
        try:
            decoded = codec.decode(bytearray(block))
            decoded_all.extend(list(decoded[0])[:k])
        except reedsolo.ReedSolomonError:
            return None
    return decoded_all


def bits_to_symbols(bits: list[int]) -> list[int]:
    symbols = []
    for i in range(0, len(bits), 8):
        chunk = bits[i:i + 8]
        val = 0
        for b in chunk:
            val = (val << 1) | b
        if len(chunk) < 8:
            val <<= (8 - len(chunk))
        symbols.append(val)
    return symbols


def symbols_to_bits(symbols: list[int], expected_bits: int | None = None) -> list[int]:
    bits = []
    for sym in symbols:
        for i in range(7, -1, -1):
            bits.append((sym >> i) & 1)
    if expected_bits is not None:
        bits = bits[:expected_bits]
    return bits
