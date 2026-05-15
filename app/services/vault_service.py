import json
import os
import time

import ecies
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from werkzeug.utils import secure_filename

from crypto.crypto_d6 import SecureVaultD6Crypto
from services.keystore_service import unwrap_user_private_keys
from repositories.document_repository import DocumentRepository
from repositories.share_repository import ShareRepository
from repositories.vault_repository import VaultRepository
from repositories.user_repository import UserRepository
from utils import create_shares

user_repository = UserRepository()
vault_repository = VaultRepository()
document_repository = DocumentRepository()
share_repository = ShareRepository()

def create_vault_document(
    owner,
    plaintext: bytes,
    source_filename: str,
    password,
    selected_trustee_ids,
    upload_folder,
    db,
):
    crypto_sym = SecureVaultD6Crypto()
    owner_enc_priv, owner_sign_priv = unwrap_user_private_keys(owner, password, crypto=crypto_sym)
    file_key = crypto_sym.generate_symmetric_key()
    nonce = crypto_sym.generate_nonce()
    aesgcm = AESGCM(file_key)

    trustees = user_repository.find_by_ids(selected_trustee_ids)
    if len(trustees) != len(selected_trustee_ids):
        raise ValueError("Uno o más fiduciarios seleccionados no existen.")

    total_shares = len(trustees)
    if total_shares < 2:
        raise ValueError("Se requieren al menos 2 fiduciarios.")
    threshold = max(2, (total_shares // 2) + 1)

    new_vault = vault_repository.create_vault(db, owner.id, threshold, status="active")

    trustee_memberships = {}
    for trustee in trustees:
        membership = vault_repository.add_trustee_membership(db, new_vault.id, trustee.id, status="active")
        trustee_memberships[trustee.id] = membership.id

    shares = create_shares(file_key, threshold, total_shares)
    recipients_data = []
    for i, trustee in enumerate(trustees):
        encrypted_share = ecies.encrypt(trustee.public_key, shares[i].encode("utf-8"))
        recipients_data.append(
            {
                "id": trustee.public_key,
                "trustee_user_id": trustee.id,
                "vault_trustee_id": trustee_memberships[trustee.id],
                "trustee_username": trustee.username,
                "encrypted_share": encrypted_share.hex(),
            }
        )

    safe_filename = secure_filename(source_filename) or "documento"

    metadata = {
        "filename": safe_filename,
        "nonce": nonce.hex(),
        "symmetric_algorithm": "AES-GCM-256",
        "asymmetric_algorithm": "ECIES-secp256k1",
        "signature_algorithm": "Ed25519",
        "creation_timestamp": time.time(),
    }
    aad_dict = {"metadata": metadata, "recipients": recipients_data}
    aad = json.dumps(aad_dict, sort_keys=True).encode("utf-8")

    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, aad)
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]
    vault_container = {
        "metadata": metadata,
        "recipients": recipients_data,
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex(),
    }

    data_to_sign = crypto_sym._get_data_to_sign(vault_container)
    signature = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(owner_sign_priv)).sign(data_to_sign)
    vault_container["signature"] = signature.hex()
    vault_container["signer_id"] = owner.signing_public_key

    # Evita colisiones de nombres entre uploads con mismo filename.
    # El id de vault es único y trazable en BD.
    vault_filename = f"vault_{new_vault.id}_{safe_filename}.vault"
    storage_path = os.path.abspath(os.path.join(upload_folder, vault_filename))
    os.makedirs(os.path.dirname(storage_path), exist_ok=True)
    new_doc = document_repository.create_document(
        db,
        vault_id=new_vault.id,
        owner_user_id=owner.id,
        filename=safe_filename,
        storage_path=storage_path,
        nonce=nonce.hex(),
        aad=aad.hex(),
    )

    for recipient in recipients_data:
        share_repository.add_share(
            db,
            document_id=new_doc.id,
            trustee_user_id=recipient["trustee_user_id"],
            vault_trustee_id=recipient["vault_trustee_id"],
            encrypted_fragment=recipient["encrypted_share"],
        )

    with open(storage_path, "w", encoding="utf-8") as output_file:
        json.dump(vault_container, output_file, indent=4)

    return new_doc
