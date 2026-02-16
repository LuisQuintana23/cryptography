# Secure Digital Document Vault
In this project, we'll design and implement a secure system for protecting, sharing, and verifying digital documents using modern applied cryptographic techniques.

## 1. System Overview
### Problem that we solve with this proyect
When a person dies without sharing access credentials to financial accounts, legal documents, or digital records, their relatives may face serious difficulties accessing essential information. At the same time, sharing full access in advance creates significant security risks during the owner’s lifetime.

This system provides a structured and secure mechanism to:
* Store sensitive documents confidentially
* Distribute future access authority among multiple trusted individuals
* Enforce a majority-based access policy (50% + 1)
* Prevent unilateral access by a single trusted person
* Protect stored data even if the storage location is compromised

The owner has its own password and two factor autentication to add, remove or alter the documents or list of trusted people. Any trusted people must create a paswword and define a two factor authentication.

For example the owner can designate 5 trusted people the required number of trusted people aproval es set al 50% + 1, For the exmple 3 persons. During the lifetime of the owner he can add or remove peolpe to the trusted list, when one person is removed all the tokens are changed to ensure the old token wont work.
### Features
* Ensure documents remain confidential during the owner’s lifetime
* Protect stored data even if the storage location is compromised
* Controlled access after death
* Define and modify list of trusted people
* Protect against unilateral misuse by a single trusted person
* Ensure integrity verification of stored data
* Enforce majority-based reconstruction policy
### Out of scope
Although we aim to solve the after dead preservation of documents there are some scenarios that we cant control:
* Automatic death verification mechanisms
* More than the number of trusted people decided to act on bad faith
* Side-channel attacks
* Biometric authentication
* The minimmun of trusted people is dead, lost acces to the system or refuses to give their token (legal procedures must be folowed)

## 2. Architecture Diagram

## 3. Security Requirements
### Confidentiality of file contents
An attacker who obtains the encrypted vault container must not be able to learn the contents of stored documents without access to the master secret or the required majority of trusted individuals.
### Integrity of file contents
The system must generate and store a cryptographic hash for every file upon upload and validate this hash against the file contents upon every retrieval to ensure data has not been altered.
### Authenticity of file sender
Trusted individuals must be able to verify that the vault was created by the legitimate owner and not by an attacker. If the vault is replaced or forged, the system must detect the lack of authenticity.
### Confidentiality of private keys
The system must encrypt all private keys in use or not in use, ensuring they are accessible only to the authenticated key owner and are never stored, logged, or exposed in plaintext.
### Protection against tampering
Any unauthorized modification of encrypted documents must be detectable before revealing decrypted content. The system must not output altered plaintext without detecting tampering.

## 4. Threat Model
### Assets
* Files: all the plain text files stored
* Master key: the key that is used to add, remove and alter the files
* Private keys: all the keys (owner and trusted people)
### Adversaries
We define the followint type of adversaries:
* External: any not trusted person that tries to acces the information
    * Attackers know the system design
    * Can read all the encripted documents
    * Can modify documents
    * Doesnt know the owner key or trusted person key
    * Cant break the encription algorithm
    * Cant recreate the master key
* Malicius trusted person: any person or group of trusted persons that doesnt reach the required tockens that tries to acces the information. 
    * Can read all the encripted documents
    * Can modify documents
    * Doesnt know the owner key
    * Cant break the encription algorithm
    * Cant recreate the master key
## 5. Trust Assumptions
To ensure the correct functionality we asume that the following is achieved:
* Users choose sufficiently strong passwords
* Secure randomness is available
* Cryptographic primitives behave as expected
* Fewer than 50% + 1 trustees collude maliciously
* Devices are not fully compromised during setup
## 6. Attack Surface Review

## 7. Design Constraints Derived from Requirements

## Core Functionalities

- Generate a unique symmetric key for each file.
- Protect file keys using recipients’ public keys (hybrid encryption).
- Digitally sign documents to guarantee authenticity.
- Verify signatures before decrypting any content.
- Protect private keys using a password-based key derivation function (KDF).
- Allow secure sharing with multiple recipients.
- Provide a basic key backup and recovery mechanism.

## Members:
 - Domínguez Chávez Jesús Abner **(Chief Testing)**
 - Hernandez Ruiz de Esparza Guillermo **(Chief Documentation)**
 - Sanchez Villlalpando Johan **(Chief Coding)**
 - Quintana Mora Luis Angel **(Chief Architecture)**
