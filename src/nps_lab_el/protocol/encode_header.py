from __future__ import annotations

from nps_lab_el.crypto.lfsr import LFSR


def encode_header_sequence(
    token_bits: list[int],
    lfsr_seed: int = 44257,
) -> list[tuple[int, int]]:
    padded = token_bits[:]
    if len(padded) % 16 != 0:
        padded.extend([0] * (16 - len(padded) % 16))
    words: list[int] = []
    for i in range(0, len(padded), 16):
        val = 0
        for b in padded[i:i + 16]:
            val = (val << 1) | b
        words.append(val)
    lfsr = LFSR(lfsr_seed)
    result: list[tuple[int, int]] = []
    for word in words:
        lfsr_val = lfsr.next()
        ip_id = word ^ lfsr_val
        icmp_seq = lfsr.next()
        result.append((ip_id & 0xFFFF, icmp_seq & 0xFFFF))
    return result


def decode_header_sequence(
    ip_ids: list[int],
    icmp_seqs: list[int],
    lfsr_seed: int = 44257,
) -> list[int] | None:
    if len(ip_ids) != len(icmp_seqs):
        return None
    lfsr = LFSR(lfsr_seed)
    words: list[int] = []
    expected_seqs: list[int] = []
    for ip_id in ip_ids:
        mask_val = lfsr.next()
        word = (ip_id ^ mask_val) & 0xFFFF
        words.append(word)
        expected_seqs.append(lfsr.next() & 0xFFFF)
    matches = sum(1 for a, b in zip(icmp_seqs, expected_seqs) if a == b)
    correlation = matches / len(icmp_seqs) if icmp_seqs else 0.0
    if correlation < 0.95:
        return None
    bits: list[int] = []
    for word in words:
        for i in range(15, -1, -1):
            bits.append((word >> i) & 1)
    return bits
