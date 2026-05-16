"""
Pruebas aisladas de `crypto.crypto_d6` (sin Flask, sin BD, sin `app/`).

Ejecutar solo cripto: `pytest tests/test_crypto_d6_unit.py`
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from crypto.crypto_d6 import SecureVaultD6Crypto


def test_wrap_unwrap_roundtrip_and_keystore_shape():
    crypto = SecureVaultD6Crypto()
    private_material = "abc123:fed456"
    wrapped = crypto.wrap_private_key(private_material, "passw0rd!")
    recovered = crypto.unwrap_private_key(json.dumps(wrapped), password="passw0rd!")
    assert recovered == private_material
    assert wrapped["kdf"]["algorithm"] == "PBKDF2-HMAC-SHA256"
    assert wrapped["wrap"]["algorithm"] == "AES-GCM-256"
    assert wrapped["key_id"]


def test_wrong_password_fails():
    crypto = SecureVaultD6Crypto()
    wrapped = crypto.wrap_private_key("owner-priv:sign-priv", "correct-password")
    with pytest.raises(ValueError):
        crypto.unwrap_private_key(json.dumps(wrapped), password="wrong-password")


def test_modified_ciphertext_fails():
    crypto = SecureVaultD6Crypto()
    wrapped = crypto.wrap_private_key("owner-priv:sign-priv", "correct-password")
    tampered = dict(wrapped)
    tampered["encrypted_key"] = wrapped["encrypted_key"][:-1] + (
        "0" if wrapped["encrypted_key"][-1] != "0" else "1"
    )
    with pytest.raises(ValueError):
        crypto.unwrap_private_key(json.dumps(tampered), password="correct-password")


def test_stolen_keystore_blob_wrong_password_cannot_decrypt():
    """Robo del blob cifrado sin la contraseña correcta: no hay material en claro."""
    crypto = SecureVaultD6Crypto()
    wrapped = crypto.wrap_private_key("enc:sign", "user-real-password")
    blob = json.dumps(wrapped)
    with pytest.raises(ValueError):
        crypto.unwrap_private_key(blob, password="not-the-password")


def test_unwrap_requires_password():
    crypto = SecureVaultD6Crypto()
    wrapped = crypto.wrap_private_key("a:b", "pw")
    with pytest.raises(ValueError):
        crypto.unwrap_private_key(json.dumps(wrapped), password=None)


def test_assert_private_keys_match_public_identity_accepts_valid_pair():
    crypto = SecureVaultD6Crypto()
    enc_priv, enc_pub = crypto.generate_encryption_keypair()
    sign_priv, sign_pub = crypto.generate_signing_keypair()
    crypto.assert_private_keys_match_public_identity(enc_priv, sign_priv, enc_pub, sign_pub)


def test_assert_private_keys_match_public_identity_rejects_wrong_encryption_pub():
    crypto = SecureVaultD6Crypto()
    enc_priv, _enc_pub = crypto.generate_encryption_keypair()
    _other_priv, wrong_enc_pub = crypto.generate_encryption_keypair()
    sign_priv, sign_pub = crypto.generate_signing_keypair()
    with pytest.raises(ValueError, match="cifrado"):
        crypto.assert_private_keys_match_public_identity(
            enc_priv, sign_priv, wrong_enc_pub, sign_pub
        )


def test_assert_private_keys_match_public_identity_rejects_wrong_signing_pub():
    crypto = SecureVaultD6Crypto()
    enc_priv, enc_pub = crypto.generate_encryption_keypair()
    sign_priv, _sign_pub = crypto.generate_signing_keypair()
    _other_priv, wrong_sign_pub = crypto.generate_signing_keypair()
    with pytest.raises(ValueError, match="firma"):
        crypto.assert_private_keys_match_public_identity(
            enc_priv, sign_priv, enc_pub, wrong_sign_pub
        )
