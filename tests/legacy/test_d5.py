import copy
from crypto_d5_signatures import SecureVaultSignedCrypto

def run_signature_tests():
    vault = SecureVaultSignedCrypto()
    print("--- INICIANDO ENTORNO DE PRUEBAS DE FIRMAS (Ed25519) ---\n")

    # 1. Generar Identidades
    # Alice será la propietaria (Owner/Signer). Bob y Charlie los receptores.
    alice_enc_priv, alice_enc_pub = vault.generate_encryption_keypair()
    alice_sign_priv, alice_sign_pub = vault.generate_signing_keypair()

    bob_enc_priv, bob_enc_pub = vault.generate_encryption_keypair()
    charlie_enc_priv, charlie_enc_pub = vault.generate_encryption_keypair()

    # Eve (Atacante) genera sus propias llaves para intentar falsificar
    eve_sign_priv, eve_sign_pub = vault.generate_signing_keypair()

    # 2. Archivo Original
    original_text = b"Este es el contenido original, altamente confidencial."
    filename = "reporte_secreto.pdf"

    # 3. Proceso Legítimo: Cifrar y Firmar
    print(">> Generando contenedor legítimo...")
    legitimate_container = vault.encrypt_and_sign(
        plaintext=original_text,
        filename=filename,
        recipient_pubkeys_hex=[bob_enc_pub, charlie_enc_pub],
        signer_privkey_hex=alice_sign_priv,
        signer_pubkey_hex=alice_sign_pub
    )
    print("Contenedor generado con éxito. Contiene firma digital.\n")


    # TEST 1: Valid signature -> file accepted
    print("TEST 1: Bob intenta descifrar un contenedor legítimo (Valid signature)")
    try:
        decrypted = vault.verify_and_decrypt(legitimate_container, bob_enc_priv)
        assert decrypted == original_text
        print("✅ Test 1 Pasado: Archivo aceptado y descifrado correctamente.\n")
    except Exception as e:
        print(f"❌ FAIL: {e}\n")

    # TEST 2: Modified ciphertext -> rejected
    print("TEST 2: Atacante modifica el Ciphertext (Modified ciphertext)")
    container_t2 = copy.deepcopy(legitimate_container)
    
    # Cambiamos un caracter del ciphertext en hexadecimal ('a' a 'b')
    h = container_t2["ciphertext"]
    container_t2["ciphertext"] = h[:-1] + ('b' if h[-1] != 'b' else 'a')

    try:
        vault.verify_and_decrypt(container_t2, bob_enc_priv)
        print("❌ FAIL: El sistema permitió un ciphertext modificado.\n")
    except ValueError as e:
        print(f"✅ Test 2 Pasado: Detectado y rechazado -> {e}\n")


    # TEST 3: Modified metadata -> rejected
    print("TEST 3: Atacante altera el nombre del archivo (Modified metadata)")
    container_t3 = copy.deepcopy(legitimate_container)
    container_t3["metadata"]["filename"] = "virus_malicioso.exe"

    try:
        vault.verify_and_decrypt(container_t3, bob_enc_priv)
        print("❌ FAIL: El sistema permitió modificar la metadata.\n")
    except ValueError as e:
        print(f"✅ Test 3 pasado: Detectado y rechazado -> {e}\n")


    # TEST 4: Wrong public key -> rejected
    print("TEST 4: Eve firma su propio archivo e intenta hacerse pasar por Alice (Wrong public key)")
    # Eve genera un contenedor nuevo pero le pone la llave pública de Alice en el "signer_id"
    # para engañar a Bob haciendo creer que el origen es Alice.
    container_t4 = vault.encrypt_and_sign(
        plaintext=b"Soy Eve, depositame muchos dolares jeje.",
        filename="factura.txt",
        recipient_pubkeys_hex=[bob_enc_pub, charlie_enc_pub],
        signer_privkey_hex=eve_sign_priv, # Eve firma con su llave
        signer_pubkey_hex=alice_sign_pub  # Eve falsifica el ID de Alice
    )

    try:
        vault.verify_and_decrypt(container_t4, bob_enc_priv)
        print("❌ FAIL: El sistema aceptó una firma generada por una llave no autorizada.\n")
    except ValueError as e:
        print(f"✅ Test 4 pasado: Falsificación de origen detectada -> {e}\n")


    # TEST 5: Signature removed -> rejected
    print("TEST 5: Atacante borra la firma del contenedor (Signature removed)")
    container_t5 = copy.deepcopy(legitimate_container)
    del container_t5["signature"]

    try:
        vault.verify_and_decrypt(container_t5, bob_enc_priv)
        print("❌ FAIL: El sistema aceptó un archivo sin firma.\n")
    except ValueError as e:
        print(f"✅ Test 5 pasado: Ausencia de firma detectada -> {e}\n")


if __name__ == "__main__":
    run_signature_tests()