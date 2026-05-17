"""
Desbloqueo de keystore (D6): un solo punto que deriva KEK, hace unwrap y valida identidad.
Las rutas y servicios de dominio no deben omitir la verificación público/privado.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from crypto.crypto_d6 import SecureVaultD6Crypto

if TYPE_CHECKING:
    from db.models import User


def unwrap_user_private_keys(user: "User", password: str, crypto: SecureVaultD6Crypto | None = None) -> tuple[str, str]:
    crypto = crypto or SecureVaultD6Crypto()
    if not user.encrypted_private_key:
        raise ValueError("El usuario no tiene keystore cifrado.")

    material = crypto.unwrap_private_key(
        user.encrypted_private_key,
        salt_hex=user.key_salt,
        nonce_hex=user.key_nonce,
        password=password,
    )
    parts = material.split(":", 1)
    if len(parts) != 2:
        raise ValueError("Formato de keystore descifrado inválido (se esperaba enc:sign).")

    enc_priv, sign_priv = parts
    if not user.public_key or not user.signing_public_key:
        raise ValueError("Usuario sin llaves públicas de identidad registradas.")

    crypto.assert_private_keys_match_public_identity(
        enc_priv,
        sign_priv,
        user.public_key,
        user.signing_public_key,
    )
    return enc_priv, sign_priv
