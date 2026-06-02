from nps_lab_el.protocol.encode_header import (
    decode_header_sequence,
    encode_header_sequence,
)


class TestHeader:
    def test_encode_decode_roundtrip(self):
        # 32 bits = 2 x 16-bit words
        bits = [1, 0, 1, 0] * 8  # 32 bits
        pairs = encode_header_sequence(bits, lfsr_seed=44257)
        ip_ids = [p[0] for p in pairs]
        icmp_seqs = [p[1] for p in pairs]
        decoded = decode_header_sequence(ip_ids, icmp_seqs, lfsr_seed=44257)
        assert decoded is not None
        assert decoded[:len(bits)] == bits

    def test_encode_produces_tuples(self):
        bits = [0] * 16
        result = encode_header_sequence(bits, lfsr_seed=44257)
        assert len(result) == 1
        assert isinstance(result[0], tuple)
        assert len(result[0]) == 2

    def test_decode_wrong_seed_returns_none(self):
        bits = [1, 0] * 16  # 32 bits
        pairs = encode_header_sequence(bits, lfsr_seed=44257)
        ip_ids = [p[0] for p in pairs]
        icmp_seqs = [p[1] for p in pairs]
        result = decode_header_sequence(ip_ids, icmp_seqs, lfsr_seed=11111)
        assert result is None

    def test_decode_mismatched_lengths_returns_none(self):
        result = decode_header_sequence([1, 2, 3], [1, 2], lfsr_seed=44257)
        assert result is None

    def test_padding_to_16bit_boundary(self):
        bits = [1, 0, 1]  # 3 bits, should be padded to 16
        pairs = encode_header_sequence(bits, lfsr_seed=44257)
        assert len(pairs) == 1  # 1 word
