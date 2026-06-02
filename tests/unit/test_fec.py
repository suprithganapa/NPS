from nps_lab_el.protocol.fec import (
    bits_to_symbols,
    rs_decode,
    rs_encode,
    symbols_to_bits,
)


class TestFEC:
    def test_rs_encode_decode_roundtrip(self):
        symbols = list(range(28))
        encoded = rs_encode(symbols, n=32, k=28)
        assert len(encoded) == 32
        decoded = rs_decode(encoded, n=32, k=28)
        assert decoded == symbols

    def test_rs_decode_corrects_errors(self):
        symbols = list(range(28))
        encoded = rs_encode(symbols, n=32, k=28)
        # Introduce 1 error
        corrupted = list(encoded)
        corrupted[0] ^= 0xFF
        decoded = rs_decode(corrupted, n=32, k=28)
        assert decoded == symbols

    def test_rs_decode_corrects_two_errors(self):
        symbols = list(range(28))
        encoded = rs_encode(symbols, n=32, k=28)
        corrupted = list(encoded)
        corrupted[0] ^= 0xFF
        corrupted[1] ^= 0xFF
        decoded = rs_decode(corrupted, n=32, k=28)
        assert decoded == symbols

    def test_bits_to_symbols_to_bits_roundtrip(self):
        bits = [1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1]
        symbols = bits_to_symbols(bits)
        result = symbols_to_bits(symbols, expected_bits=len(bits))
        assert result == bits

    def test_bits_to_symbols_packing(self):
        # 8 bits -> 1 symbol
        bits = [1, 0, 0, 0, 0, 0, 0, 1]  # 0x81 = 129
        symbols = bits_to_symbols(bits)
        assert symbols == [129]

    def test_symbols_to_bits_truncation(self):
        symbols = [0xFF]
        bits = symbols_to_bits(symbols, expected_bits=4)
        assert len(bits) == 4
        assert bits == [1, 1, 1, 1]
