# Signatures & Authentication
## Signature Design
### Algorithm chosen
We implemented the Edwards-curve Digital Signature Algorithm (Ed25519) as our primary cryptographic signing mechanism. This modern standard provides a solution that lets us generate highly compact and computationally efficient signatures, making it ideal for our hybrid encryption architecture.

The primary advantage of Ed25519 over traditional ECDSA or RSA is its deterministic nature. It does not rely on the operating system's random number generator (RNG) at the exact moment of signing. Instead, it generates the required nonce securely based on the private key and the message itself. This eliminates a class of catastrophic implementation vulnerabilities related to poor entropy or nonce reuse, which historically allows attackers to extract private keys from standard ECDSA implementations.


### What data is signed
The digital signature encompasses a strict aggregation of all security-relevant data within the vault container. Specifically, the system serializes a JSON payload that includes the metadata dictionary, the full recipient list with their encrypted keys, the ciphertext, and the AES-GCM authentication tag. The only excluded elements are the signature itself and the signer's public key identifier.

By signing this comprehensive dataset rather than just the file contents, we achieve a robust cryptographic binding between the encrypted payload and its surrounding context. The main advantage is that it provides absolute tamper evidence; any unauthorized alteration to the file's intent, its authorized users, or its metadata will instantly invalidate the signature, forcing the system to reject the container safely.


### Why hashing is required before signing
Our system implements the "Hash-then-Sign" paradigm by processing the serialized container data through a collision-resistant cryptographic hash function—specifically SHA-512, which is natively integrated into our Ed25519 implementation—before applying the digital signature. This step is strictly required because asymmetric cryptographic algorithms operate on fixed-size mathematical groups and are computationally incapable of directly encrypting or signing arbitrarily large amounts of data, such as high-resolution documents or databases.

The primary advantage of this approach is extreme computational efficiency and payload scalability. Hashing solves the size limitation by mathematically reducing any file, regardless of its original size, into a unique 64-byte digest. Because modern cryptographic hashes are strictly collision-resistant, signing this small digest provides the exact same mathematical integrity guarantee as signing the original large file. This allows the elliptic curve algorithm to perform its complex validations in milliseconds, completely preventing system resource exhaustion while supporting files of unlimited size.


## Security Decisions
### Why sign ciphertext and not plaintext?
Our system strictly enforces the "Encrypt-then-Sign" paradigm, meaning the digital signature is applied to the AES-GCM ciphertext rather than the original plaintext document. This architectural decision ensures that the recipient can mathematically verify the exact origin and integrity of the cryptographic container as it arrived, without needing to access the underlying sensitive data first.

The main advantage of this approach is the mitigation of "Surreptitious Forwarding" attacks. If we signed the plaintext, a malicious but legitimate recipient could decrypt the file, extract the valid signature, and re-encrypt it for an unauthorized third party, falsely making it appear as a direct communication from the original sender. Signing the ciphertext permanently binds the sender's identity to that exact, unique encrypted package, preventing unauthorized re-packaging.


### What happens if the signature is not verified first?
The cryptographic architecture mandates that signature verification acts as the absolute first step in the data ingestion pipeline, strictly adhering to the "Verify-before-Decrypt" principle. If the mathematical validation of the Ed25519 signature fails, the system immediately aborts the process, throws an exception, and safely purges the untrusted data from memory before any other modules execute.

Failing to verify the signature first violates the Cryptographic Doom Principle. If the system attempts to parse or decrypt untrusted ciphertext before confirming its authentic origin, an attacker could supply maliciously crafted data designed to exploit vulnerabilities in the decryption library. The distinct advantage of verifying first is that it acts as a cryptographic firewall, dropping malicious payloads at the perimeter before they can trigger memory corruption, buffer overflows, or key leakage within the complex decryption logic.


### What happens if metadata is excluded?
