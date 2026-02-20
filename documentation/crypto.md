# Cryptographic Protocol

The cryptographic infrastructure guarantees **Zero-Knowledge Architecture**, protecting message contents with complete confidentiality, integration, and authenticity via End-to-End Encryption (E2E).

## Encryption Standards

Our implementation applies primitives mirroring the renowned **Signal Protocol**:

1. **X3DH (Extended Triple Diffie-Hellman):** Initiates session establishment via asynchronous key exchange.
2. **Double Ratchet Algorithm:** Ensures perfect forward secrecy, computing a new ephemeral key per message transaction without exposing future or past secrets if a key compromise occurs.
3. **AES-256-GCM:** The robust block cipher orchestrating the symmetric content encryption and authenticated tag generation.
4. **Ed25519:** Applied for identity-proof operations, issuing long-lasting digital user signatures.
5. **X25519:** Dictates standard elliptic-curve Diffie-Hellman key agreement procedures.
6. **Argon2id:** Memory-hard cryptographic hashing applied strictly to user authentication passwords and salted verifications.
7. **HKDF-SHA256:** Determines cryptographic root and chained derivations.

## Key Hierarchy Tree

```
Identity Keys (Ed25519)
    │
    ├── Signed Prekeys (X25519)
    │
    ├── One-Time Prekeys (X25519)
    │
    └── Session Keys
            │
            ├── Root Key (HKDF-SHA256)
            │
            └── Chain Key
                    │
                    └── Message Keys (AES-256-GCM)
```

## Considerations & Guarantees
- **No Plaintext Persistence:** The backend only receives unreadable ciphertexts (and heavily authenticated tokens).
- **Key Rotation:** Occurs asynchronously per `Double Ratchet` progression.
- **Server Agnosticism:** The server acts purely as an opaque delivery/storage mechanism, incapable of performing decryption.
