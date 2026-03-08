import os
from crypto_AESGCM_D2 import SecureVaultCrypto

def save_container(folder_name, aad, nonce, ciphertext):
    """Función auxiliar para guardar los archivos físicos del contenedor """
    os.makedirs(folder_name, exist_ok=True)
    with open(os.path.join(folder_name, "header"), "wb") as f:
        f.write(aad)
    with open(os.path.join(folder_name, "nonce"), "wb") as f:
        f.write(nonce)
    with open(os.path.join(folder_name, "ciphertext"), "wb") as f:
        f.write(ciphertext)
    return folder_name

def read_container(folder_name):
    """Función auxiliar para leer los archivos físicos del contenedor"""
    with open(os.path.join(folder_name, "header"), "rb") as f:
        aad = f.read()
    with open(os.path.join(folder_name, "nonce"), "rb") as f:
        nonce = f.read()
    with open(os.path.join(folder_name, "ciphertext"), "rb") as f:
        ciphertext = f.read()
    return aad, nonce, ciphertext

def run_visible_tests():
    crypto = SecureVaultCrypto()
    data = b"Contenido super secreto para mi proyecto de criptografia."
    filename = "documento_secreto.txt"
    
    print("=== INICIANDO PRUEBAS DEL MÓDULO ===\n")

    # Test 1: Encrypt -> decrypt returns identical file
    print("Test 1: Encriptar y desencriptar retorna archivo idéntico")
    key1, nonce1, ct1, aad1 = crypto.encrypt_file(data, filename)
    folder1 = save_container("vault_container_test1", aad1, nonce1, ct1)
    
    # Leemos desde los archivos físicos
    r_aad1, r_nonce1, r_ct1 = read_container(folder1)
    decrypted_data = crypto.decrypt_file(key1, r_nonce1, r_ct1, r_aad1)
    if decrypted_data == data:
        print(f"  -> ÉXITO: El texto desencriptado es idéntico. Contenedor guardado en '{folder1}/'")

    # Test 2: Wrong key fails
    print("\nTest 2: Falla con la llave incorrecta")
    key2, nonce2, ct2, aad2 = crypto.encrypt_file(data, filename)
    folder2 = save_container("vault_container_test2", aad2, nonce2, ct2)
    
    wrong_key = crypto.generate_key()
    r_aad2, r_nonce2, r_ct2 = read_container(folder2)
    try:
        crypto.decrypt_file(wrong_key, r_nonce2, r_ct2, r_aad2)
        print("  -> ERROR: ¡Se pudo desencriptar con la llave incorrecta!")
    except ValueError as e:
        print(f"  -> ÉXITO (Fallo esperado detectado): {e}. Contenedor guardado en '{folder2}/'")

    # Test 3: Modified ciphertext fails
    print("\nTest 3: Falla si se modifica el ciphertext")
    key3, nonce3, ct3, aad3 = crypto.encrypt_file(data, filename)
    folder3 = save_container("vault_container_test3", aad3, nonce3, ct3)
    
    # Simulamos el ataque: abrimos el archivo y modificamos el primer byte
    with open(os.path.join(folder3, "ciphertext"), "r+b") as f:
        byte = f.read(1)
        f.seek(0)
        f.write(bytes([byte[0] ^ 1])) # Invertimos un bit
        
    r_aad3, r_nonce3, r_ct3 = read_container(folder3)
    try:
        crypto.decrypt_file(key3, r_nonce3, r_ct3, r_aad3)
    except ValueError as e:
        print(f"  -> ÉXITO (Fallo esperado detectado): {e}. Contenedor modificado guardado en '{folder3}/'")

    # Test 4: Modified metadata fails
    print("\nTest 4: Falla si se modifican los metadatos (header)")
    key4, nonce4, ct4, aad4 = crypto.encrypt_file(data, filename)
    folder4 = save_container("vault_container_test4", aad4, nonce4, ct4)
    
    # Simulamos el ataque: modificamos el archivo de metadatos (header)
    with open(os.path.join(folder4, "header"), "wb") as f:
        tampered_aad = aad4.replace(b"documento_secreto", b"archivo_hackeado")
        f.write(tampered_aad)
        
    r_aad4, r_nonce4, r_ct4 = read_container(folder4)
    try:
        crypto.decrypt_file(key4, r_nonce4, r_ct4, r_aad4)
    except ValueError as e:
        print(f"  -> ÉXITO (Fallo esperado detectado): {e}. Contenedor modificado guardado en '{folder4}/'")

    # Test 5: Multiple encryptions produce different ciphertexts
    print("\nTest 5: Múltiples encriptaciones producen ciphertexts diferentes")
    key5a, nonce5a, ct5a, aad5a = crypto.encrypt_file(data, filename)
    folder5a = save_container("vault_container_test5a", aad5a, nonce5a, ct5a)
    
    key5b, nonce5b, ct5b, aad5b = crypto.encrypt_file(data, filename) # Encriptamos el MISMO archivo otra vez
    folder5b = save_container("vault_container_test5b", aad5b, nonce5b, ct5b)
    
    r_aad5a, r_nonce5a, r_ct5a = read_container(folder5a)
    r_aad5b, r_nonce5b, r_ct5b = read_container(folder5b)
    
    if r_ct5a != r_ct5b:
        print(f"  -> ÉXITO: Los archivos ciphertext son distintos. Contenedores guardados en '{folder5a}/' y '{folder5b}/'")

if __name__ == '__main__':
    run_visible_tests()