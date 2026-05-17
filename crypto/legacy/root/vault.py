# Archivo: vault.py
# Utiliza los scripts para leer y escribir en disco y coordinar los procesos
import os
import json
import symmetric
import asymmetric
import container

class SecureVault:
    def encrypt_to_file(self, input_filepath: str, output_filepath: str, recipient_pubkeys_hex: list[str]):
        """Lee un archivo físico, orquesta la encriptación híbrida y guarda el .vault."""
        if len(recipient_pubkeys_hex) < 2:
            raise ValueError("El sistema debe soportar al menos 2 destinatarios según los requerimientos.")

        with open(input_filepath, "rb") as f:
            plaintext = f.read()

        filename = os.path.basename(input_filepath)
        
        # 1. Simétrico: Generar llave y nonce
        file_key = symmetric.generate_symmetric_key()
        nonce = symmetric.generate_nonce()

        # 2. Asimétrico: Encriptar la llave simétrica para cada destinatario
        recipients_data = []
        for pubkey in recipient_pubkeys_hex:
            enc_key = asymmetric.encrypt_file_key(pubkey, file_key)
            recipients_data.append({"id": pubkey, "encrypted_key": enc_key})

        # 3. Contenedor: Construir AAD
        header_dict = container.build_header(filename, recipients_data)
        aad = container.serialize_aad(header_dict)

        # 4. Simétrico: Encriptar archivo
        ciphertext_with_tag = symmetric.encrypt_data(file_key, nonce, plaintext, aad)

        # 5. Guardar contenedor estructurado
        vault_data = {
            "header_json": aad.decode('utf-8'),
            "nonce": nonce.hex(),
            "ciphertext_with_tag": ciphertext_with_tag.hex()
        }

        with open(output_filepath, "w", encoding="utf-8") as f:
            json.dump(vault_data, f, indent=4)

    def decrypt_from_file(self, container_filepath: str, output_filepath: str, user_privkey_hex: str):
        """Lee un .vault, orquesta el descifrado híbrido y restaura el archivo físico."""
        with open(container_filepath, "r", encoding="utf-8") as f:
            vault_data = json.load(f)

        aad = vault_data["header_json"].encode('utf-8')
        nonce = bytes.fromhex(vault_data["nonce"])
        ciphertext_with_tag = bytes.fromhex(vault_data["ciphertext_with_tag"])
        header_dict = json.loads(vault_data["header_json"])

        # 1. Asimétrico & Contenedor: Identificar al usuario y extraer su llave encriptada
        user_pubkey = asymmetric.derive_pubkey(user_privkey_hex)
        encrypted_file_key_hex = container.find_encrypted_key_for_user(header_dict, user_pubkey)

        # 2. Asimétrico: Descifrar la llave simétrica
        file_key = asymmetric.decrypt_file_key(user_privkey_hex, encrypted_file_key_hex)

        # 3. Simétrico: Descifrar el archivo verificando el AAD
        plaintext = symmetric.decrypt_data(file_key, nonce, ciphertext_with_tag, aad)

        # 4. Guardar archivo recuperado
        with open(output_filepath, "wb") as f:
            f.write(plaintext)