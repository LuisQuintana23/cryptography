# Archivo: container.py
# Estructura del archivo JSON .vault y manejando AAD
import json
import time

def build_header(filename: str, recipients_data: list[dict]) -> dict:
    """Construye el diccionario de la cabecera que incluye metadatos y destinatarios."""
    return {
        "metadata": {
            "filename": filename,
            "symmetric_algorithm": "AES-GCM-256",
            "asymmetric_algorithm": "ECIES-secp256k1",
            "creation_timestamp": time.time()
        },
        "recipients": recipients_data
    }

def serialize_aad(header_dict: dict) -> bytes:
    """Serializa la cabecera de forma determinista para usarla como AAD."""
    return json.dumps(header_dict, sort_keys=True).encode('utf-8')

def find_encrypted_key_for_user(header_dict: dict, user_pubkey_hex: str) -> str:
    """Busca la llave encriptada correspondiente al identificador del usuario."""
    for recipient in header_dict.get("recipients", []):
        if recipient["id"] == user_pubkey_hex:
            return recipient["encrypted_key"]
            
    raise PermissionError("Acceso Denegado: Tu identificador no está en la lista de destinatarios autorizados.")