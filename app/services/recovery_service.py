import json

import ecies
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto.crypto_d6 import SecureVaultD6Crypto
from services.keystore_service import unwrap_user_private_keys
from repositories.share_repository import ShareRepository
from repositories.vault_repository import VaultRepository
from utils import reconstruct_key

share_repository = ShareRepository()
vault_repository = VaultRepository()


def release_share_and_maybe_decrypt(db, user, share):
    doc = share.document
    active_trustees_count = vault_repository.count_active_trustees(doc.vault_id)
    if active_trustees_count < 2:
        raise ValueError("La bóveda tiene menos de 2 fiduciarios activos. No es recuperable.")

    threshold = max(2, doc.vault.threshold)
    if threshold > active_trustees_count:
        raise ValueError("La política actual de umbral es inconsistente con fiduciarios activos.")

    released_shares = share_repository.list_released_for_document(doc.id)
    if len(released_shares) < threshold:
        return {
            "type": "json",
            "status_code": 200,
            "payload": {
                "status": "success",
                "message": f"Firma válida. Se han reunido {len(released_shares)} de {threshold} tokens necesarios.",
            },
        }

    with open(doc.storage_path, "r", encoding="utf-8") as input_file:
        vault_container = json.load(input_file)

    crypto_sym = SecureVaultD6Crypto()
    if "signature" not in vault_container or "signer_id" not in vault_container:
        raise ValueError("Acceso Denegado: Credenciales inválidas o contenedor comprometido.")

    data_to_verify = crypto_sym._get_data_to_sign(vault_container)
    try:
        pub_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(vault_container["signer_id"]))
        pub_key_obj.verify(bytes.fromhex(vault_container["signature"]), data_to_verify)
    except InvalidSignature:
        raise ValueError("Acceso Denegado: Credenciales inválidas o contenedor comprometido.")

    shares_list = [s.plain_fragment for s in released_shares]
    file_key = reconstruct_key(shares_list)
    nonce = bytes.fromhex(vault_container["metadata"]["nonce"])
    aad_dict = {"metadata": vault_container["metadata"], "recipients": vault_container["recipients"]}
    aad = json.dumps(aad_dict, sort_keys=True).encode("utf-8")
    ciphertext_with_tag = bytes.fromhex(vault_container["ciphertext"]) + bytes.fromhex(vault_container["tag"])

    try:
        plaintext = AESGCM(file_key).decrypt(nonce, ciphertext_with_tag, aad)
    except InvalidTag:
        raise ValueError("Acceso Denegado: Credenciales inválidas o contenedor comprometido.")

    return {
        "type": "file",
        "status_code": 200,
        "filename": vault_container["metadata"]["filename"],
        "content": plaintext,
    }


def decrypt_and_store_share_fragment(db, user, share, password: str):
    crypto_sym = SecureVaultD6Crypto()
    trustee_enc_priv, _ = unwrap_user_private_keys(user, password, crypto=crypto_sym)
    encrypted_frag_bytes = bytes.fromhex(share.encrypted_fragment)
    plain_frag_bytes = ecies.decrypt(trustee_enc_priv, encrypted_frag_bytes)
    share.plain_fragment = plain_frag_bytes.decode("utf-8")
    db.session.commit()


def validate_identity_payload(
    encrypted_private_key: str,
    salt: str,
    nonce: str,
    password: str,
    *,
    expected_encryption_pub: str | None = None,
    expected_signing_pub: str | None = None,
):
    crypto_sym = SecureVaultD6Crypto()
    material = crypto_sym.unwrap_private_key(
        encrypted_private_key,
        salt_hex=salt,
        nonce_hex=nonce,
        password=password,
    )
    parts = material.split(":", 1)
    if len(parts) != 2:
        raise ValueError("El archivo de identidad contiene material de llave en formato inválido.")

    enc_priv, sign_priv = parts
    if expected_encryption_pub and expected_signing_pub:
        crypto_sym.assert_private_keys_match_public_identity(
            enc_priv,
            sign_priv,
            expected_encryption_pub,
            expected_signing_pub,
        )
    elif expected_encryption_pub or expected_signing_pub:
        raise ValueError("Metadatos de identidad incompletos: faltan llaves públicas esperadas.")
