import json
import time
import hashlib

from crypto_d2 import SecureVaultCrypto
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SecureVaultD6Crypto(SecureVaultCrypto):
    def __init__(self):
        super().__init__()
        self.KDF_ALGORITHM = "PBKDF2-HMAC-SHA256"
        self.KDF_ITERATIONS = 480000
        self.WRAP_ALGORITHM = "AES-GCM-256"
        self.WRAP_VERSION = 1
        self.WRAP_AAD = b"secure_vault_private_key_wrap"

    def derive_key_from_password(self, password: str, salt: bytes = None) -> tuple[bytes, bytes]:
        # Mantiene mismo flujo de D2, pero parametrizado por metadata D6.
        self.KEY_SIZE = 32
        return super().derive_key_from_password(password, salt)

    def wrap_private_key(self, private_key_hex: str, password: str) -> dict:
        kek, salt = self.derive_key_from_password(password)
        aesgcm = AESGCM(kek)
        nonce = self.generate_nonce()
        ciphertext = aesgcm.encrypt(nonce, private_key_hex.encode("utf-8"), self.WRAP_AAD)
        key_id = hashlib.sha256(private_key_hex.encode("utf-8")).hexdigest()[:32]

        return {
            "wrap_version": self.WRAP_VERSION,
            "key_id": key_id,
            "kdf": {
                "algorithm": self.KDF_ALGORITHM,
                "iterations": self.KDF_ITERATIONS,
                "salt": salt.hex(),
            },
            "wrap": {
                "algorithm": self.WRAP_ALGORITHM,
                "nonce": nonce.hex(),
                "aad": self.WRAP_AAD.decode("utf-8"),
            },
            "encrypted_key": ciphertext.hex(),
            "created_at": time.time(),
            # Compatibilidad temporal
            "salt": salt.hex(),
            "nonce": nonce.hex(),
        }

    def unwrap_private_key(self, encrypted_key_hex: str, salt_hex: str = None, nonce_hex: str = None, password: str = None) -> str:
        if password is None:
            raise ValueError("Se requiere contraseña para desbloquear llaves.")

        salt = None
        nonce = None
        ciphertext = None

        if isinstance(encrypted_key_hex, str):
            try:
                keystore = json.loads(encrypted_key_hex)
                if isinstance(keystore, dict) and "encrypted_key" in keystore and "kdf" in keystore and "wrap" in keystore:
                    salt = bytes.fromhex(keystore["kdf"]["salt"])
                    nonce = bytes.fromhex(keystore["wrap"]["nonce"])
                    ciphertext = bytes.fromhex(keystore["encrypted_key"])
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                pass

        if salt is None or nonce is None or ciphertext is None:
            if not salt_hex or not nonce_hex:
                raise ValueError("Material de keystore incompleto.")
            salt = bytes.fromhex(salt_hex)
            nonce = bytes.fromhex(nonce_hex)
            ciphertext = bytes.fromhex(encrypted_key_hex)

        kek, _ = self.derive_key_from_password(password, salt)
        aesgcm = AESGCM(kek)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, self.WRAP_AAD)
            return plaintext.decode("utf-8")
        except InvalidTag:
            raise ValueError("Acceso denegado: Contraseña incorrecta o llave corrupta.")
