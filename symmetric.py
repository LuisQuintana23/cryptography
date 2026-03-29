import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

NONCE_SIZE = 12
KEY_SIZE = 32

def generate_symmetric_key() -> bytes:
    """Genera la llave simétrica (File Key) de 256 bits."""
    return AESGCM.generate_key(bit_length=KEY_SIZE * 8)

def generate_nonce() -> bytes:
    """Genera un nonce seguro de 12 bytes."""
    return os.urandom(NONCE_SIZE)

def encrypt_data(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Cifra los datos y vincula el AAD. Retorna el ciphertext con el tag integrado."""
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, plaintext, aad)

def decrypt_data(key: bytes, nonce: bytes, ciphertext_with_tag: bytes, aad: bytes) -> bytes:
    """Descifra y verifica la integridad de los datos y el AAD."""
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
    except InvalidTag:
        raise ValueError("¡Alerta de Seguridad! El contenedor o los metadatos han sido modificados.")