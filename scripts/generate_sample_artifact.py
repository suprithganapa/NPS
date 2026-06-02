#!/usr/bin/env python3
"""Generate sample DRM artifacts for testing."""

import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    artifacts_dir = project_root / "artifacts"
    artifacts_dir.mkdir(exist_ok=True)

    # 1. Generate random AES-256 key (32 bytes)
    key = os.urandom(32)

    # 2. Split into key_partial (28 bytes) and key_fragment (4 bytes)
    key_partial = key[:28]
    key_fragment = key[28:]

    # 3. Sample plaintext
    plaintext = b"NPS LAB EL - Sample protected content for DRM demo.\n"

    # 4. Generate 12-byte random nonce
    nonce = os.urandom(12)

    # 5. AAD
    aad = b"nps-lab-el-v1"

    # 6. Encrypt with AES-GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    # 7. Save encrypted data
    enc_path = artifacts_dir / "sample.enc"
    enc_path.write_bytes(ciphertext)

    # 8. Compute SHA-256 of plaintext
    plaintext_sha256 = hashlib.sha256(plaintext).hexdigest()

    # 9. Save manifest
    manifest = {
        "artifact": "sample.enc",
        "nonce_b64": base64.b64encode(nonce).decode(),
        "key_partial_b64": base64.b64encode(key_partial).decode(),
        "key_fragment_b64": base64.b64encode(key_fragment).decode(),
        "aad_b64": base64.b64encode(aad).decode(),
        "plaintext_sha256": plaintext_sha256,
    }
    manifest_path = artifacts_dir / "sample.manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

    # 10. Print summary
    print("Sample DRM artifact generated")
    print(f"  Encrypted file : {enc_path}")
    print(f"  Manifest       : {manifest_path}")
    print(f"  Ciphertext size: {len(ciphertext)} bytes")
    print(f"  Nonce (b64)    : {manifest['nonce_b64']}")
    print(f"  Key partial    : {len(key_partial)} bytes")
    print(f"  Key fragment   : {len(key_fragment)} bytes (not saved)")
    print(f"  Plaintext SHA  : {plaintext_sha256}")


if __name__ == "__main__":
    main()
