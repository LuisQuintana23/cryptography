import json
import time
import hashlib

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from coincurve.utils import get_valid_secret
from eth_keys import keys
import os


class SecureVaultD6Crypto:
    def __init__(self):
        # AES-GCM recomienda un nonce de 12 bytes (96 bits)
        self.NONCE_SIZE = 12
        # Tamaño de llave de 256 bits para máxima seguridad
        self.KEY_SIZE = 32
        self.KDF_ALGORITHM = "PBKDF2-HMAC-SHA256"
        self.KDF_ITERATIONS = 480000
        self.WRAP_ALGORITHM = "AES-GCM-256"
        self.WRAP_VERSION = 1
        self.WRAP_AAD = b"secure_vault_private_key_wrap"

    def generate_nonce(self) -> bytes:
        return os.urandom(self.NONCE_SIZE)

    def generate_symmetric_key(self) -> bytes:
        """Genera llave simétrica (File Key) para AES-GCM."""
        return AESGCM.generate_key(bit_length=self.KEY_SIZE * 8)

    def generate_encryption_keypair(self) -> tuple[str, str]:
        """Genera llaves secp256k1 para cifrado (Confidencialidad)."""
        secret = get_valid_secret()
        priv_key = keys.PrivateKey(secret)
        return priv_key.to_hex(), priv_key.public_key.to_hex()

    def generate_signing_keypair(self) -> tuple[str, str]:
        """Genera llaves Ed25519 para firmas digitales (Autenticidad)."""
        priv_key = ed25519.Ed25519PrivateKey.generate()
        priv_bytes = priv_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return priv_bytes.hex(), pub_bytes.hex()

    def derive_key_from_password(self, password: str, salt: bytes = None) -> tuple[bytes, bytes]:
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.KDF_ITERATIONS,
        )
        kek = kdf.derive(password.encode("utf-8"))
        return kek, salt

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

    @staticmethod
    def _hex_norm(value: str) -> str:
        s = (value or "").strip().lower()
        return s[2:] if s.startswith("0x") else s

    def assert_private_keys_match_public_identity(
        self,
        enc_priv_hex: str,
        sign_priv_hex: str,
        expected_enc_pub_hex: str,
        expected_sign_pub_hex: str,
    ) -> None:
        """
        Tras unwrap, garantiza que no hay ambigüedad: el material descifrado corresponde
        exactamente a las llaves públicas registradas (ECIES + Ed25519).
        """
        try:
            enc_priv_clean = self._hex_norm(enc_priv_hex)
            derived_enc_pub = keys.PrivateKey(bytes.fromhex(enc_priv_clean)).public_key.to_hex()
        except Exception as err:
            raise ValueError("Material de llave de cifrado inválido.") from err

        if self._hex_norm(derived_enc_pub) != self._hex_norm(expected_enc_pub_hex):
            raise ValueError(
                "Identidad criptográfica inconsistente: la llave privada de cifrado no corresponde a la pública registrada."
            )

        try:
            sign_priv_clean = self._hex_norm(sign_priv_hex)
            sk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sign_priv_clean))
            derived_sign_pub = sk.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ).hex()
        except Exception as err:
            raise ValueError("Material de llave de firma inválido.") from err

        if self._hex_norm(derived_sign_pub) != self._hex_norm(expected_sign_pub_hex):
            raise ValueError(
                "Identidad criptográfica inconsistente: la llave privada de firma no corresponde a la pública registrada."
            )

    def _get_data_to_sign(self, container_dict: dict) -> bytes:
        """
        Define estrictamente qué se firma/verifica:
        metadata + recipients + ciphertext + tag.
        """
        sign_payload = {
            "metadata": container_dict["metadata"],
            "recipients": container_dict["recipients"],
            "ciphertext": container_dict["ciphertext"],
            "tag": container_dict["tag"],
        }
        return json.dumps(sign_payload, sort_keys=True).encode("utf-8")
