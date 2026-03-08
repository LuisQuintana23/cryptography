# Secure Symmetric Encryption Module
This module is one of the main components of the vault proyect, it provides a secure way to encrypt and decrypt files using the AES-GCM algorithm. The module is designed to return the encrypted data in a specific format. The requirements for this module are:
- Ensure confidentiality, integrity and tamper detection
- Generate a new symmetric key for each file
- Bind metadata to the encrypted data
- Use AEAD 
- Manage nonces securely
- Include, authenticate and protect against silently modicication of the metadata
- Detect tampering of the encrypted data or metadata
- The output must be a container with the following content:
>   vault_container/ <br>
    ├── header <br>
    ├── nonce <br>
    ├── ciphertext <br>
    └── authentication_tag <br>

## Encryption Design
### Selected AEAD algorithm
We implemented AES-GCM (Advanced Encryption Standard in Galois/Counter Mode) using the cryptography.hazmat.primitives.ciphers.aead library. This algorithm provides both confidentiality, integrity and is n authenticated encryption with associated data (AEAD) algorithm. 

### Key size
The system generates a fresh symmetric key of 256 bits (32 bytes) for each individual file to ensure maximum security. 

### Nonce strategy
We use a 96-bit (12 bytes) nonce, which is the recommended size for AES-GCM. The nonce is generated dynamically for every encryption operation using the OS-provided cryptographically secure pseudorandom number generator. The generated nonce is stored alongside the ciphertext in the vault container.

### Metadata authentication strategy
We include the following metadata:
- filename
- algorithm_version
- encryption_parameters:
    - key_size_bits
    - nonce_size_bytes
    - tag_size_bytes
- creation_timestamp
This information is serialized into a JSON object and passed directly to the AES-GCM algorithm as Associated Authenticated Data (AAD), binding the metadata to the ciphertext.

The generated output is a vault container that includes the header, nonce and the ciphertext. The authentication_tag is appended to the end of the ciphertext byte string by the Python cryptography library. The library automatically handles the generation and verification of the authentication tag, ensuring that any tampering with the ciphertext or metadata will be detected during decryption.

## Security Decisions
### Why AEAD instead of encryption + hash?
Combining encryption and a separate hash manually (such as MAC-then-Encrypt) is notoriously difficult to implement securely and often leads to software implementation bugs. By using an AEAD primitive like AES-GCM, we guarantee both confidentiality and authenticity in a single, standardized operation, eliminating the risk of manually gluing primitives together and ensuring they are combined correctly by design.

### What happens if nonce repeats?
GCM uses a polynomial MAC for authentication (Galois Message Authentication Code). Reusing a nonce allows an attacker to solve the polynomial equations and extract the authentication subkey (the hash key). Once this key is compromised, the attacker can forge valid authentication tags for any arbitrary ciphertext, completely destroying the integrity guarantees of the vault.

### What attacker are you defending against?
On our architecture design we identified the storage, encripted file container and public keys as untrusted components. Therefore this module defends against an External Attacker or a compromised storage provider (e.g., a malicious cloud admin) who has full read and write access to the stored vault_container at rest. By implementing AEAD and binding the metadata as Associated Authenticated Data (AAD), we ensure that any single-bit alteration to either the ciphertext or the metadata will immediately invalidate the authentication tag.

We defined in the threat model 2 possible attackers:
- External Attacker: 
    - Their capability: We assume they know our system design, can read all the encrypted documents, and can attempt to modify them, but they cannot mathematically break the encryption algorithm nor do they possess any keys.

    - Our defense: The confidentiality of AES-256 ensures the content is indistinguishable from random noise. If the attacker attempts to modify the ciphertext to corrupt data or alters the header file, our use of Associated Authenticated Data (AAD) and the Authentication Tag guarantees that the tampering is detected immediately, failing securely.
- Malicious Trusted Person:
    - Their capability: They have access to the containers and might try to alter the vault to delete files, inject fraudulent versions, or modify the context of the documents before the rest of the trusted people gather their keys.

    - Our defense: At the level of this file encryption module, a trusted person without the reconstructed master key has the exact same limitations as an external attacker regarding the ciphertext. The AEAD scheme prevents silent modifications (Tamper Detection). If they alter a single bit of the encrypted file or its metadata, the decryption operation will abort with an InvalidTag exception, protecting the system's integrity and preventing forged information from being delivered.