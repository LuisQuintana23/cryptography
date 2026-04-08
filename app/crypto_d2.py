import os
import json
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

class SecureVaultCrypto:
    def __init__(self):
        # AES-GCM recomienda un nonce de 12 bytes (96 bits)
        self.NONCE_SIZE = 12 
        # Tamaño de llave de 256 bits para máxima seguridad
        self.KEY_SIZE = 32

    """
    Deriva una llave de 32 bytes (KEK) a partir de una contraseña humana.
    Retorna la llave derivada y el salt utilizado.
    """
    def derive_key_from_password(self, password: str, salt: bytes = None) -> tuple[bytes, bytes]:

        if salt is None:
            salt = os.urandom(16) # Salt se guardará en la BD
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE, # 32 bytes, lo que necesita AES-GCM
            salt=salt,
            iterations=480000, # Recomendación actual de OWASP
        )
        
        key = kdf.derive(password.encode('utf-8'))
        return key, salt

    def wrap_private_key(self, private_key_hex: str, password: str) -> dict:
        """Cifra la llave privada usando la contraseña del usuario."""
        # Derivar la KEK
        kek, salt = self.derive_key_from_password(password)
        
        # Preparar AES-GCM
        aesgcm = AESGCM(kek)
        nonce = self.generate_nonce()
        
        # Datos Asociados Autenticados (AAD) para contexto
        aad = b"secure_vault_private_key_wrap"
        
        # Cifrar la llave privada
        ciphertext = aesgcm.encrypt(nonce, private_key_hex.encode('utf-8'), aad)
        
        # Retornamos todo en formato hexadecimal para guardarlo fácilmente en SQLite
        return {
            "salt": salt.hex(),
            "nonce": nonce.hex(),
            "encrypted_key": ciphertext.hex()
        }
    
    def unwrap_private_key(self, encrypted_key_hex: str, salt_hex: str, nonce_hex: str, password: str) -> str:
        """Descifra la llave privada del usuario utilizando su contraseña."""
        salt = bytes.fromhex(salt_hex)
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(encrypted_key_hex)
        
        # Derivar la KEK original
        kek, _ = self.derive_key_from_password(password, salt)
        
        aesgcm = AESGCM(kek)
        aad = b"secure_vault_private_key_wrap"
        
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
            return plaintext.decode('utf-8')
        except InvalidTag:
            raise ValueError("Acceso denegado: Contraseña incorrecta o llave corrupta.")

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
        
        # AESGCM adjunta automáticamente el Authentication Tag al final del ciphertext
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