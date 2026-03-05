import os
import json
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

class SecureVaultCrypto:
    def __init__(self):
        # AES-GCM recomienda un nonce de 12 bytes (96 bits)
        self.NONCE_SIZE = 12 
        # Tamaño de llave de 256 bits para máxima seguridad
        self.KEY_SIZE = 32

    def generate_key(self) -> bytes:
        """Genera una llave simétrica fresca por archivo."""
        return AESGCM.generate_key(bit_length=self.KEY_SIZE * 8)

    def generate_nonce(self) -> bytes:
        """Genera un nonce seguro usando el RNG del OS."""
        return os.urandom(self.NONCE_SIZE)

    def encrypt_file(self, plaintext: bytes, filename: str) -> tuple[bytes, bytes, bytes, bytes]:
        """
        Cifra el contenido del archivo y vincula los metadatos.
        Retorna: (llave, nonce, ciphertext_con_tag, metadatos_serializados)
        """
        # Generar una llave fresca por archivo
        key = self.generate_key()
        aesgcm = AESGCM(key)
        
        # Generar nonce único
        nonce = self.generate_nonce()
        
        # Proteger metadatos (AAD)
        metadata = {
            "filename": filename,
            "algorithm_version": "AES-GCM-256",
            "encryption_parameters": {
                "key_size_bits": self.KEY_SIZE * 8,
                "nonce_size_bytes": self.NONCE_SIZE,
                "tag_size_bytes": 16 # Tamaño estándar del MAC en AES-GCM con PyPi
            },
            "creation_timestamp": time.time()
        }
        aad = json.dumps(metadata, sort_keys=True).encode('utf-8')
        
        # Encriptar: AESGCM adjunta automáticamente el Authentication Tag al final del ciphertext
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
        
        return key, nonce, ciphertext, aad

    def decrypt_file(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        """
        Descifra el archivo y verifica la integridad del ciphertext y los metadatos.
        """
        aesgcm = AESGCM(key)
        try:
            # decrypt lanzará InvalidTag si el ciphertext o el AAD (metadatos) fueron modificados
            plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
            return plaintext
        except InvalidTag:
            # Fallar de forma segura si la autenticación falla
            raise ValueError("¡Alerta de Seguridad! El archivo o los metadatos han sido modificados o la llave es incorrecta.")