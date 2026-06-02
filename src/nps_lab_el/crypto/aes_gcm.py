import hmac
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_artifact(plaintext: bytes, key: bytes, aad: bytes | None = None) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return ciphertext, nonce


def decrypt_artifact(ciphertext: bytes, key: bytes, nonce: bytes, aad: bytes | None = None) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)


def generate_key_material() -> tuple[bytes, bytes]:
    key = os.urandom(32)
    return key[:28], key[28:]


def compute_key_fragment_hmac(key_deriv: bytes, totp_counter: int, src_ip: str) -> bytes:
    message = totp_counter.to_bytes(8, byteorder="big") + src_ip.encode()
    digest = hmac.new(key_deriv, message, hashlib.sha256).digest()
    return digest[:4]
