import os
import json
from vault import SecureVault
import asymmetric

def run_physical_tests():
    boveda = SecureVault()
    
    # Nombres descriptivos para los archivos generados
    original_file = "00_original_secreto.txt"
    vault_file = "01_contenedor_legitimo.vault"
    alice_decrypted = "02_descifrado_por_alice.txt"
    bob_decrypted = "03_descifrado_por_bob.txt"
    tampered_vault_1 = "04_corrupto_test3_id_alterado.vault"
    tampered_vault_2 = "05_corrupto_test5_bob_borrado.vault"

    print("--- Configurando Entorno Físico Modular ---")
    # Ahora llamamos a la generación de llaves desde el módulo asimétrico
    alice_priv, alice_pub = asymmetric.generate_keypair()
    bob_priv, bob_pub = asymmetric.generate_keypair()
    eve_priv, eve_pub = asymmetric.generate_keypair() # Atacante

    # Crear el archivo original físico
    with open(original_file, "w", encoding="utf-8") as f:
        f.write("Este es el secreto clasificado del entregable D3 guardado en disco usando módulos separados.")

    # Encriptar a un archivo físico .vault
    boveda.encrypt_to_file(original_file, vault_file, [alice_pub, bob_pub])
    print(f"Contenedor físico generado: {vault_file}\n")

    # TEST 1: Archivo compartido con 2 usuarios y ambos pueden descifrar.
    print("Test 1: Alice y Bob pueden descifrar el archivo físico...")
    boveda.decrypt_from_file(vault_file, alice_decrypted, alice_priv)
    boveda.decrypt_from_file(vault_file, bob_decrypted, bob_priv)
    
    # Verificamos integridad byte por byte
    with open(original_file, "rb") as f1, open(alice_decrypted, "rb") as fa, open(bob_decrypted, "rb") as fb:
        original_data = f1.read()
        assert fa.read() == original_data
        assert fb.read() == original_data
    print("✅ Test 1 Pasado: Ambos usuarios restauraron los archivos físicos con éxito.")

    # TEST 2: Usuario no autorizado no puede descifrar.
    print("\nTest 2: Eve (no autorizada) intenta descifrar el archivo físico...")
    try:
        boveda.decrypt_from_file(vault_file, "eve_no_deberia_existir.txt", eve_priv)
        assert False, "Eve no debió poder descifrar"
    except PermissionError as e:
        print(f"✅ Test 2 Pasado: {e}")

    # TEST 3: Lista de destinatarios alterada en el archivo físico.
    print("\nTest 3: Atacante altera el ID de Bob en un archivo nuevo...")
    with open(vault_file, "r", encoding="utf-8") as f:
        tampered_data = json.load(f)
    
    header_dict = json.loads(tampered_data["header_json"])
    header_dict["recipients"][1]["id"] = "id_modificado"
    tampered_data["header_json"] = json.dumps(header_dict, sort_keys=True)
    
    with open(tampered_vault_1, "w", encoding="utf-8") as f:
        json.dump(tampered_data, f, indent=4)
        
    try:
        boveda.decrypt_from_file(tampered_vault_1, "fail_3_no_deberia_existir.txt", alice_priv)
        assert False, "Debió fallar por InvalidTag"
    except ValueError as e:
        print(f"✅ Test 3 Pasado: {e}")

    # TEST 4: Llave privada equivocada.
    print("\nTest 4: Alice intenta usar una llave privada incorrecta...")
    wrong_priv, _ = asymmetric.generate_keypair()
    try:
        boveda.decrypt_from_file(vault_file, "fail_4_no_deberia_existir.txt", wrong_priv)
        assert False, "Debió fallar la desencriptación ECIES"
    except (PermissionError, ValueError) as e:
        print(f"✅ Test 4 Pasado: Bloqueado correctamente. ({e})")

    # TEST 5: Remover un destinatario rompe el acceso.
    print("\nTest 5: Atacante borra a Bob del archivo .vault...")
    with open(vault_file, "r", encoding="utf-8") as f:
        tampered_data_2 = json.load(f)
        
    header_dict_2 = json.loads(tampered_data_2["header_json"])
    header_dict_2["recipients"].pop() 
    tampered_data_2["header_json"] = json.dumps(header_dict_2, sort_keys=True)
    
    with open(tampered_vault_2, "w", encoding="utf-8") as f:
        json.dump(tampered_data_2, f, indent=4)
        
    try:
        boveda.decrypt_from_file(tampered_vault_2, "fail_5_no_deberia_existir.txt", alice_priv)
        assert False, "Debió fallar por InvalidTag"
    except ValueError as e:
        print(f"✅ Test 5 Pasado: {e}")

    print("\n✨ Pruebas modulares finalizadas. Revisa tu carpeta para ver los archivos generados.")

if __name__ == "__main__":
    run_physical_tests()