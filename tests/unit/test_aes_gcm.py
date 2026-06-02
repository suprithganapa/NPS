import pytest

from nps_lab_el.crypto.aes_gcm import (
    compute_key_fragment_hmac,
    decrypt_artifact,
    encrypt_artifact,
    generate_key_material,
)


class TestAesGcm:
    def test_encrypt_decrypt_roundtrip(self):
        key = b"\x00" * 32
        plaintext = b"hello world"
        ciphertext, nonce = encrypt_artifact(plaintext, key)
        result = decrypt_artifact(ciphertext, key, nonce)
        assert result == plaintext

    def test_encrypt_decrypt_with_aad(self):
        key = b"\x01" * 32
        plaintext = b"secret data"
        aad = b"additional"
        ciphertext, nonce = encrypt_artifact(plaintext, key, aad=aad)
        result = decrypt_artifact(ciphertext, key, nonce, aad=aad)
        assert result == plaintext

    def test_tampered_ciphertext_raises(self):
        key = b"\x00" * 32
        plaintext = b"hello"
        ciphertext, nonce = encrypt_artifact(plaintext, key)
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        with pytest.raises(Exception):
            decrypt_artifact(bytes(tampered), key, nonce)

    def test_generate_key_material_sizes(self):
        partial, fragment = generate_key_material()
        assert len(partial) == 28
        assert len(fragment) == 4

    def test_compute_key_fragment_hmac_produces_4_bytes(self):
        result = compute_key_fragment_hmac(b"some_key", 12345, "10.0.0.1")
        assert len(result) == 4
        assert isinstance(result, bytes)

    def test_compute_key_fragment_hmac_deterministic(self):
        a = compute_key_fragment_hmac(b"key", 1, "1.2.3.4")
        b = compute_key_fragment_hmac(b"key", 1, "1.2.3.4")
        assert a == b
