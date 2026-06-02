from nps_lab_el.models.auth import AuthToken, KeyMaterial


class TestAuthToken:
    def test_total_bits(self):
        assert AuthToken.total_bits() == 328

    def test_to_bits_from_bits_roundtrip(self):
        token = AuthToken(
            payload=b"\xAB" * 16,
            totp_counter=123456,
            channel_mask=0x0F,
            mac=b"\xCD" * 16,
        )
        bits = token.to_bits()
        assert len(bits) == 328
        recovered = AuthToken.from_bits(bits)
        assert recovered.payload == token.payload
        assert recovered.totp_counter == token.totp_counter
        assert recovered.channel_mask == token.channel_mask
        assert recovered.mac == token.mac

    def test_to_bits_length(self):
        token = AuthToken(
            payload=b"\x00" * 16,
            totp_counter=0,
            channel_mask=0,
            mac=b"\x00" * 16,
        )
        assert len(token.to_bits()) == 328

    def test_bits_are_binary(self):
        token = AuthToken(
            payload=b"\xFF" * 16,
            totp_counter=999,
            channel_mask=255,
            mac=b"\xFF" * 16,
        )
        bits = token.to_bits()
        assert all(b in (0, 1) for b in bits)


class TestKeyMaterial:
    def test_key_full_concatenation(self):
        partial = b"\x01" * 28
        fragment = b"\x02" * 4
        km = KeyMaterial(key_partial=partial, key_fragment=fragment)
        assert km.key_full == partial + fragment
        assert len(km.key_full) == 32
