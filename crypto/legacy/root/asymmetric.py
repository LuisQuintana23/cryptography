from coincurve.utils import get_valid_secret
from eth_keys import keys
import ecies

def generate_keypair() -> tuple[str, str]:
    """Genera un par de llaves asimétricas secp256k1. Retorna (priv_hex, pub_hex)."""
    secret = get_valid_secret()
    priv_key = keys.PrivateKey(secret)
    return priv_key.to_hex(), priv_key.public_key.to_hex()

def derive_pubkey(privkey_hex: str) -> str:
    """Deriva la llave pública a partir de una llave privada en formato hexadecimal."""
    priv_key_bytes = bytes.fromhex(privkey_hex.replace('0x', ''))
    return keys.PrivateKey(priv_key_bytes).public_key.to_hex()

def encrypt_file_key(pubkey_hex: str, file_key: bytes) -> str:
    """Cifra la llave simétrica usando la llave pública del destinatario."""
    encrypted = ecies.encrypt(pubkey_hex, file_key)
    return encrypted.hex()

def decrypt_file_key(privkey_hex: str, encrypted_file_key_hex: str) -> bytes:
    """Descifra la llave simétrica usando la llave privada del destinatario."""
    try:
        encrypted_bytes = bytes.fromhex(encrypted_file_key_hex)
        return ecies.decrypt(privkey_hex, encrypted_bytes)
    except Exception:
        raise ValueError("Fallo al descifrar la llave simétrica. Llave privada incorrecta o datos corruptos.")