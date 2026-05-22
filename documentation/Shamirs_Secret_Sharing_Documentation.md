# Distributed Key Management (Shamir's Secret Sharing)

## Why Shamir's Secret Sharing is Used

The system strictly mandates a "50% + 1" consensus threshold rule to authorize the release of digital inheritance vaults. Traditional cryptographic approaches fail to implement this securely: simply encrypting the document multiple times for multiple recipients allows any single rogue trustee to decrypt it independently, while multi-signature schemes require complex, real-time interactive coordination.

To solve this, we implemented **Shamir's Secret Sharing (SSS)** as our core Key Management layer. SSS provides **Information-Theoretic Security (Perfect Secrecy)**, this means that an adversary possessing fewer shares than the required threshold ($k-1$) has mathematically zero information about the underlying secret. It eliminates single points of failure by ensuring the system tolerates the loss of a minority of trustees while strictly preventing unauthorized individual or premature access.

## How Shamir is Implemented

A critical architectural constraint of our system is that **Shamir's Secret Sharing never touches, encrypts, or decrypts the actual file payload**. SSS is mathematically inefficient for heavy data processing. Instead, it operates exclusively on the 256-bit symmetric file key.

### 1\. The Sealing Phase (Splitting)

During the `/upload` process, the system generates a random 256-bit master file key to encrypt the document via AES-GCM. Once data encryption is complete, that master key is passed into the SSS module (`utils.py -> create\_shares`). SSS generates an unpredictable polynomial of degree $k-1$ and distributes specific coordinate points (shares) to each trustee. The master key is immediately destroyed from server memory.

### 2\. The Release Phase (Reconstruction)

During the `/release` process, as trustees authenticate and unlock their individual tokens, the system collects the decrypted shares. Once the threshold count is satisfied, the system applies **Lagrange Polynomial Interpolation** (`utils.py -> reconstruct\_key`) to resolve the equations and reconstruct the exact 256-bit master file key. This key is then fed directly into the symmetric engine to decrypt the file.

## Cryptographic Division of Labor

To ensure a clean separation of concerns and address architectural requirements, responsibilities are strictly partitioned as follows:

|Cryptographic Primitive|Domain Responsibility|
|-|-|
|**AES-GCM-256 (D2)**|**Data Confidentiality \& Integrity:** Encrypts and decrypts the bulk file payload rapidly.|
|**Shamir's Secret Sharing**|**Access Consensus Management:** Divides and reconstructs the 256-bit master AES key.|
|**ECIES-secp256k1**|**Key Delivery Privacy:** Asymmetrically wraps individual Shamir shares for secure transit.|
|**Ed25519 (D5)**|**Origin Authenticity \& Non-Repudio:** Signs the entire container to prove ownership and immutability.|

## Security Validation \& Testing

The SSS engine was rigorously validated through automated unit and integration boundary testing:

* **Insufficient Quorum Test:** Validated that providing $k-1$ shares triggers an unresolvable mathematical state. The system cannot perform interpolation, forcing the recovery pipeline to drop the request and maintain a safe, locked state.
* **Share Tampering \& Corruption Test:** If an attacker modifies a share within the database or file container, the Lagrange interpolation still runs but yields an entirely incorrect, garbage 256-bit key. When this faulty key is applied to the decryption layer, the AES-GCM authentication tag validation immediately fails, raising an `InvalidTag` exception and executing a secure **Fail-Closed** routine.

## Module Documentation Reference

* **Module Location:** `utils.py` (Isolated mathematical utility function).
* **Input Parameters:** \* `secret`: 256-bit master key (bytes).

  * `threshold` ($k$): Minimum shares required to reconstruct $max (2, (totalshares // 2) + 1)$.
  * `totalshares` ($n$): Total active fiduciarios assigned to the vault.
* **Output Parameters:** An array of $n$ unique coordinate strings (hex-encoded text strings) representing the distributed shares.
