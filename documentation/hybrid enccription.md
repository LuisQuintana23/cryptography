# Hybrid Encryption
## Why Hybrid Encryption is Used
Public-key cryptography (asymmetric encryption) is computationally expensive and mathematically restricted by size limits, making it insecure and highly inefficient for encrypting large files directly. Hybrid encryption solves this by combining the performance and unlimited payload capacity of symmetric cryptography (to encrypt the file) with the secure distribution properties of asymmetric cryptography. Furthermore, to enforce the system's "50%+1" consensus requirement without keeping plaintext keys on the server, Shamir's Secret Sharing is injected as a critical key management layer bridging the two.
## Why Symmetric Encryption is Still Needed
Symmetric encryption is strictly required to handle the actual file payload. We use an AEAD symmetric cipher (AES-GCM-256) because it processes large streams of data rapidly while simultaneously generating an authentication tag. This tag guarantees the integrity and authenticity of both the file contents and the metadata, which asymmetric encryption alone cannot easily provide for large files.
### The Role of Shamir's Secret Sharing & Per-Recipient Distribution
To securely enforce the threshold rule, the system cannot give the complete symmetric key to any single user, as this would violate the consensus requirement. Instead, the system isolates the generated AES-GCM key and applies **Shamir's Secret Sharing (SSS)**.

Shamir does not encrypt data; it is a mathematical interpolation function used to split the 256-bit AES key into polynomial fragments (shares). Once the key is split, the system uses **ECIES** to asymmetrically encrypt (wrap) each mathematical fragment individually, using the unique public key of each trustee. This ensures that no single user possesses the master key, but authorized users can securely unwrap their specific shares and combine them to mathematically reconstruct the original AES key once the 50%+1 threshold is met.

This ensures that access remains strictly collaborative, requiring a majority to unwrap and reconstruct the secret.
## Security Decisions
### How do Recipients Identify Their Key?
Recipients are identified deterministically using their public key. When the file is encrypted, the system stores each recipient's hex-encoded public key as their id inside the recipients array within the container's header. During decryption, the system derives the user's public key from their provided private key and searches the header for the matching id to locate their specific encrypted file key.
## What Happens if Attacker Modifies Recipient List?
The entire recipient list IDs and keys are embedded inside the JSON header. This entire header is serialized and passed into the AES-GCM cipher as Associated Authenticated Data (AAD). If an attacker attempts to add a new recipient, remove an existing one, or swap identities, the cryptographic binding is broken. Upon decryption, the AES-GCM tag validation will fail, raising an InvalidTag exception and safely halting the process before any data is revealed.
## What Happens if Public Key is Wrong?
If the sender uses the wrong public key during the encryption phase, the system will encrypt the symmetric file key for an unintended mathematical recipient. When the actual authorized user attempts to open the vault, their private key will not mathematically correspond to the public key used for wrapping. The ECIES decryption process will fail to unwrap the file key, raising a ValueError ("Fallo al descifrar la llave simétrica") and completely denying access to the vault contents.
