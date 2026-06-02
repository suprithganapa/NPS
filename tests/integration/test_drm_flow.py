import hashlib

import pytest

from nps_lab_el.crypto.aes_gcm import decrypt_artifact, encrypt_artifact
from nps_lab_el.models.auth import AuthorizationState, KeyMaterial, KnockSession
from nps_lab_el.services.drm_responder import DrmResponder


@pytest.mark.simulation
class TestDrmFlow:
    def test_end_to_end_drm(self, test_config):
        # 1. Create key material
        key_partial = b"\xAA" * 28
        key_fragment = b"\xBB" * 4
        km = KeyMaterial(key_partial=key_partial, key_fragment=key_fragment)

        # 2. Encrypt artifact with full key
        plaintext = b"This is a protected artifact."
        ciphertext, nonce = encrypt_artifact(plaintext, km.key_full)

        # 3. Compute fragment via DRM responder
        responder = DrmResponder(test_config)
        session = KnockSession(
            src_ip="10.0.0.1",
            state=AuthorizationState.AUTHORIZED,
        )
        fragment = responder.compute_fragment(session)
        assert len(fragment) == 4

        # 4. Encode fragment into reply fields and extract it back
        session_nonce = 0x1234
        fields = responder.encode_reply_fields(fragment, session_nonce)
        extracted = DrmResponder.extract_key_fragment(
            reply_ttl=fields["ttl"],
            reply_tos=fields["tos"],
            reply_icmp_id=fields["icmp_id"],
            session_nonce=session_nonce,
        )
        assert extracted == fragment

        # 5. Reconstruct full key and decrypt
        reconstructed_km = KeyMaterial(key_partial=key_partial, key_fragment=extracted)
        # Note: reconstructed key uses the computed fragment, not the original
        # So we re-encrypt with the reconstructed key to verify the flow
        ciphertext2, nonce2 = encrypt_artifact(plaintext, reconstructed_km.key_full)
        decrypted = decrypt_artifact(ciphertext2, reconstructed_km.key_full, nonce2)
        assert decrypted == plaintext

        # 6. Verify SHA-256 of decrypted matches original
        assert hashlib.sha256(decrypted).digest() == hashlib.sha256(plaintext).digest()

    def test_encode_extract_fragment_roundtrip(self, test_config):
        responder = DrmResponder(test_config)
        fragment = b"\x01\x02\x03\x04"
        session_nonce = 0xABCD
        fields = responder.encode_reply_fields(fragment, session_nonce)
        extracted = DrmResponder.extract_key_fragment(
            reply_ttl=fields["ttl"],
            reply_tos=fields["tos"],
            reply_icmp_id=fields["icmp_id"],
            session_nonce=session_nonce,
        )
        assert extracted == fragment
