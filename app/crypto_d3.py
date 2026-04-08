import os
import json
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from coincurve.utils import get_valid_secret
from eth_keys import keys
import ecies

class SecureVaultHybridCrypto:
    def __init__(self):
        self.NONCE_SIZE = 12
        self.KEY_SIZE = 32

    def generate_symmetric_key(self) -> bytes:
        """Genera la llave simétrica (File Key) de 256 bits."""
        return AESGCM.generate_key(bit_length=self.KEY_SIZE * 8)

    def generate_nonce(self) -> bytes:
        return os.urandom(self.NONCE_SIZE)

    def generate_keypair(self) -> tuple[str, str]:
        """Genera un par de llaves asimétricas secp256k1."""
        secret = get_valid_secret()
        priv_key = keys.PrivateKey(secret)
        return priv_key.to_hex(), priv_key.public_key.to_hex()

    def encrypt_file(self, plaintext: bytes, filename: str, recipient_pubkeys_hex: list[str]) -> dict:
        """Cifra el archivo y genera el contenedor híbrido para múltiples destinatarios."""
        if len(recipient_pubkeys_hex) < 2:
            raise ValueError("El sistema debe soportar al menos 2 destinatarios.")

        file_key = self.generate_symmetric_key()
        aesgcm = AESGCM(file_key)
        nonce = self.generate_nonce()

        recipients = []
        for pubkey_hex in recipient_pubkeys_hex:
            encrypted_file_key = ecies.encrypt(pubkey_hex, file_key)
            recipients.append({
                "id": pubkey_hex,
                "encrypted_key": encrypted_file_key.hex()
            })

        metadata = {
            "filename": filename,
            "nonce": nonce.hex(),  # <-- Nonce en la metadata
            "symmetric_algorithm": "AES-GCM-256",
            "asymmetric_algorithm": "ECIES-secp256k1",
            "creation_timestamp": time.time()
        }

        aad_dict = {"metadata": metadata, "recipients": recipients}
        aad = json.dumps(aad_dict, sort_keys=True).encode('utf-8')
        
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, aad)

        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]

        # JSON final
        return {
            "metadata": metadata,
            "recipients": recipients,
            "ciphertext": ciphertext.hex(),
            "tag": tag.hex()
        }

    def decrypt_file(self, container: dict, user_privkey_hex: str) -> bytes:
        """Descifra el archivo extrayendo la llave simétrica correspondiente al usuario."""
        aad_dict = {"metadata": container["metadata"], "recipients": container["recipients"]}
        aad = json.dumps(aad_dict, sort_keys=True).encode('utf-8')
        
        # Extraemos el nonce desde la metadata
        nonce = bytes.fromhex(container["metadata"]["nonce"]) 
        
        ciphertext = bytes.fromhex(container["ciphertext"])
        tag = bytes.fromhex(container["tag"])
        ciphertext_with_tag = ciphertext + tag

        priv_key_bytes = bytes.fromhex(user_privkey_hex.replace('0x', ''))
        user_pubkey_hex = keys.PrivateKey(priv_key_bytes).public_key.to_hex()

        encrypted_file_key_hex = None
        for recipient in container["recipients"]:
            if recipient["id"] == user_pubkey_hex:
                encrypted_file_key_hex = recipient["encrypted_key"]
                break

        if not encrypted_file_key_hex:
            raise PermissionError("Acceso Denegado: Tu identificador no está en la lista de destinatarios autorizados.")

        try:
            encrypted_file_key = bytes.fromhex(encrypted_file_key_hex)
            file_key = ecies.decrypt(user_privkey_hex, encrypted_file_key)
        except Exception:
            raise ValueError("Fallo al descifrar la llave del archivo.")

        aesgcm = AESGCM(file_key)
        try:
            return aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
        except InvalidTag:
            raise ValueError("¡Alerta de Seguridad! El contenedor ha sido modificado o la metadata fue alterada.")

    def encrypt_to_file(self, input_filepath: str, output_filepath: str, recipient_pubkeys_hex: list[str]):
        """Lee un archivo físico, lo cifra y guarda el contenedor híbrido (.vault)."""
        with open(input_filepath, "rb") as f:
            plaintext = f.read()

        filename = os.path.basename(input_filepath)
        container = self.encrypt_file(plaintext, filename, recipient_pubkeys_hex)

        with open(output_filepath, "w", encoding="utf-8") as f:
            json.dump(container, f, indent=4)

    def decrypt_from_file(self, container_filepath: str, output_filepath: str, user_privkey_hex: str):
        """Lee un contenedor híbrido (.vault), lo descifra y guarda el archivo original."""
        with open(container_filepath, "r", encoding="utf-8") as f:
            container = json.load(f)

        plaintext = self.decrypt_file(container, user_privkey_hex)

        with open(output_filepath, "wb") as f:
            f.write(plaintext)