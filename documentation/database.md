# Database Schema

All system persistence is executed inside a centralized **PostgreSQL 16** relational database. The schema leverages normalization separated across distinct logical tables aligned with the isolated microservices functionality.

## Core Tables Overview

### 1. Account Management
Provides domain models for user verification.

- **`users`**
    - `id` (UUID Primary Key)
    - `username` (Varchar, Unique, Indexed)
    - `email` (Varchar, Unique)
    - `password_hash` (Argon2id Hash Blob)
    - `created_at` / `updated_at` (Timestamps)
    - `is_active` (Boolean Flag)

### 2. Cryptographic Storage
Retains public materials essential to establish End-to-End Encryption sessions. Never stores private keys.

- **`identity_keys`**
    - Stores the long-term `Ed25519` pub-key mappings for digital signature validation.
- **`signed_prekeys`**
    - Stores the medium-term `X25519` key for X3DH bootstrapping.
- **`one_time_prekeys`**
    - Plentiful pool of single-use `X25519` ephemeral public keys, consumed on a per-session connection basis.

### 3. Messaging Ecosystem
Records stateful references pertaining to group rooms and their relationships.

- **`conversations`**
    - Maps unique room identities (Individual/Group typings).
- **`conversation_members`**
    - Tracks many-to-many relationship of users existing in conversations with distinct Role based permissions (`member`, `admin`, `owner`).
- **`messages`**
    - The core ledger. Stores the securely evaluated `content` column strictly as byte arrays encrypted by AES-GCM. Correlated to `sender_id` and `conversation_id`.

### 4. File Storage Metadata
Holds file relationship attributes. Actual file blobs remain encrypted and pass through to object storage like MinIO.

- **`files`**
    - Identifies basic object properties like `filename`, `size`, `content_type` alongside its `encrypted_key` (The wrapper key mapped back to the active user's session state context).
