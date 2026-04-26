import os
import json
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag, InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from coincurve.utils import get_valid_secret
from eth_keys import keys
import ecies

class SecureVaultSignedCrypto:
    def __init__(self, trusted_signers: set[str] = None):
        self.NONCE_SIZE = 12
        self.KEY_SIZE = 32
        self.trusted_signers = trusted_signers or set()

    # GENERACIÓN DE LLAVES
    def generate_symmetric_key(self) -> bytes:
        return AESGCM.generate_key(bit_length=self.KEY_SIZE * 8)

    def generate_nonce(self) -> bytes:
        return os.urandom(self.NONCE_SIZE)

    def generate_encryption_keypair(self) -> tuple[str, str]:
        """Genera llaves secp256k1 para el cifrado (Confidencialidad)."""
        secret = get_valid_secret()
        priv_key = keys.PrivateKey(secret)
        return priv_key.to_hex(), priv_key.public_key.to_hex()

    def generate_signing_keypair(self) -> tuple[str, str]:
        """Genera llaves Ed25519 para las firmas digitales (Autenticidad)."""
        priv_key = ed25519.Ed25519PrivateKey.generate()
        priv_bytes = priv_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_bytes = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return priv_bytes.hex(), pub_bytes.hex()

    # LÓGICA DE FIRMA Y VALIDACIONES BASE
    def _get_data_to_sign(self, container_dict: dict) -> bytes:
        """
        Define estrictamente qué se firma: Metadata + Recipients + Ciphertext + Tag.
        """
        sign_payload = {
            "metadata": container_dict["metadata"],
            "recipients": container_dict["recipients"],
            "ciphertext": container_dict["ciphertext"],
            "tag": container_dict["tag"]
        }
        return json.dumps(sign_payload, sort_keys=True).encode('utf-8')

    def _normalize_pubkey(self, key_hex: str) -> str:
        return key_hex.lower().replace("0x", "")

    def _validate_metadata_content(self, metadata: dict):
        required = ["filename", "nonce", "symmetric_algorithm", "asymmetric_algorithm", "signature_algorithm"]
        for field in required:
            if field not in metadata:
                raise ValueError(f"Rechazado: Metadata incompleta, falta '{field}'.")

    # FLUJO PRINCIPAL: CIFRAR Y FIRMAR
    def encrypt_and_sign(self, plaintext: bytes, filename: str, recipient_pubkeys_hex: list[str], signer_privkey_hex: str, signer_pubkey_hex: str) -> dict:
        if len(recipient_pubkeys_hex) < 2:
            raise ValueError("Se requieren al menos 2 destinatarios.")

        # 1. Cifrado Simétrico (D2)
        file_key = self.generate_symmetric_key()
        aesgcm = AESGCM(file_key)
        nonce = self.generate_nonce()

        # 2. Cifrado Asimétrico de la Llave (D3)
        recipients = []
        for pubkey_hex in recipient_pubkeys_hex:
            encrypted_file_key = ecies.encrypt(pubkey_hex, file_key)
            recipients.append({
                "id": pubkey_hex,
                "encrypted_key": encrypted_file_key.hex()
            })

        # 3. Empaquetar Metadatos (Conservamos el timestamp como registro histórico)
        metadata = {
            "filename": filename,
            "nonce": nonce.hex(),
            "symmetric_algorithm": "AES-GCM-256",
            "asymmetric_algorithm": "ECIES-secp256k1",
            "signature_algorithm": "Ed25519",
            "creation_timestamp": time.time()
        }

        aad_dict = {"metadata": metadata, "recipients": recipients}
        aad = json.dumps(aad_dict, sort_keys=True).encode('utf-8')
        
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, aad)
        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]

        # 4. Construir contenedor base (Sin firma aún)
        container = {
            "metadata": metadata,
            "recipients": recipients,
            "ciphertext": ciphertext.hex(),
            "tag": tag.hex()
        }

        # 5. Generar Firma Digital (Hash -> Sign)
        data_to_sign = self._get_data_to_sign(container)
        priv_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(signer_privkey_hex))
        signature = priv_key_obj.sign(data_to_sign)

        # 6. Añadir firma y estructura final requerida
        container["signature"] = signature.hex()
        container["signer_id"] = signer_pubkey_hex

        return container
    
    # FLUJO PRINCIPAL: VERIFICAR Y DESCIFRAR
    def verify_and_decrypt(self, container: dict, user_privkey_hex: str) -> bytes:
        
        # Campos obligatorios
        required_fields = ["metadata", "recipients", "ciphertext", "tag", "signature", "signer_id"]
        for field in required_fields:
            if field not in container:
                raise ValueError(f"Rechazado: Falta el campo obligatorio '{field}' en el contenedor.")

        if not isinstance(container["recipients"], list) or len(container["recipients"]) == 0:
            raise ValueError("Rechazado: Lista de destinatarios inválida.")

        if not isinstance(container["metadata"], dict):
            raise ValueError("Rechazado: Metadata inválida.")

        # Validar metadata contenido
        self._validate_metadata_content(container["metadata"])

        # Validar longitudes críticas
        if len(bytes.fromhex(container["metadata"]["nonce"])) != self.NONCE_SIZE:
            raise ValueError("Rechazado: Nonce inválido.")

        if len(bytes.fromhex(container["tag"])) != 16:
            raise ValueError("Rechazado: Tag inválido.")

        # Validar firmante confiable
        signer_id_norm = self._normalize_pubkey(container["signer_id"])
        if self.trusted_signers and signer_id_norm not in self.trusted_signers:
            raise ValueError("Rechazado: El firmante no es de confianza.")

        # 1. Verificar presencia de firma
        if "signature" not in container or "signer_id" not in container:
            raise ValueError("Rechazado: El contenedor no tiene firma digital o falta el signer_id.")

        # 2. VERIFICACIÓN DE FIRMA DIGITAL
        data_to_verify = self._get_data_to_sign(container)
        try:
            pub_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(container["signer_id"]))
            pub_key_obj.verify(bytes.fromhex(container["signature"]), data_to_verify)
        except InvalidSignature:
            raise ValueError("Rechazado: Firma digital inválida. El origen no es auténtico o el archivo/metadata fue modificado.")
        except Exception:
            raise ValueError("Rechazado: Error al procesar la llave pública del firmante.")

        # 3. Si la firma es válida, procedemos a descifrar (Flujo D3 normal)
        aad_dict = {"metadata": container["metadata"], "recipients": container["recipients"]}
        aad = json.dumps(aad_dict, sort_keys=True).encode('utf-8')
        nonce = bytes.fromhex(container["metadata"]["nonce"]) 
        ciphertext_with_tag = bytes.fromhex(container["ciphertext"]) + bytes.fromhex(container["tag"])

        priv_key_bytes = bytes.fromhex(user_privkey_hex.replace('0x', ''))
        user_pubkey_hex = self._normalize_pubkey(
            keys.PrivateKey(priv_key_bytes).public_key.to_hex()
        )

        encrypted_file_key_hex = None
        for recipient in container["recipients"]:
            if self._normalize_pubkey(recipient["id"]) == user_pubkey_hex:
                encrypted_file_key_hex = recipient["encrypted_key"]
                break

        if not encrypted_file_key_hex:
            raise PermissionError("Rechazado: Tu identificador no está en la lista de destinatarios.")

        try:
            file_key = ecies.decrypt(user_privkey_hex, bytes.fromhex(encrypted_file_key_hex))
        except Exception:
            raise ValueError("Rechazado: Fallo al descifrar la llave del archivo.")

        aesgcm = AESGCM(file_key)
        try:
            return aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
        except InvalidTag:
            raise ValueError("Rechazado: Modificación detectada durante el descifrado simétrico.")