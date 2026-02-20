# API Documentation

The Secure Messenger acts as a RESTful web application built to facilitate a secure, encrypted messaging experience. All client traffic passes through the API Gateway, which handles rate limiting, CORS, and proxying to downstream microservices.

## Base URL Reference

- **REST Base Path:** `http(s)://<domain>:8080/api/v1`
- **WebSocket Path:** `ws(s)://<domain>:8080/ws`

## Authentication API (`/auth`)

Handled by the **Auth Service**. All subsequent sensitive endpoints expect a valid JWT (`Authorization: Bearer <token>`).

### User Management
- `POST /auth/register`: Create a new user account returning JWT tokens.
- `POST /auth/login`: Authenticate an existing user returning JWT tokens.
- `POST /auth/refresh`: Refresh an expired access token using a valid refresh token.
- `POST /auth/logout`: Invalidate a user's session cache.

## Key Distribution API (`/keys`)

Handled by the **Key Service**. Implements key-exchange necessary for the Signal Protocol integration.

### Keys Life-Cycle
- `POST /keys/identity`: Upload the permanent Ed25519 identity key and signature.
- `GET /keys/identity/{user_id}`: Fetch the identity key of a requested peer.
- `POST /keys/signed-prekey`: Upload a signed prekey for X3DH initialization.
- `GET /keys/bundle/{user_id}`: Retrieve a specific user's `PreKeyBundle` required to establish an initial cipher-text session.
- `POST /keys/one-time-prekeys`: Upload a batch of one-time prekeys to the server key pool.

## Messaging API (`/conversations` and `/messages`)

Handled by the **Message Service**. Enables asynchronous historical viewing and real-time chat creation.

### Managing Conversations
- `POST /conversations`: Create a new conversation (P2P or group mode).
- `GET /conversations/{id}/messages`: Fetch encrypted message history of a specific conversation ID.

### Real-Time WebSocket Connection
- **Endpoint:** `GET /ws`
- Upgrades the connection to a bi-directional persistent WebSocket for the exchange of:
  - Incoming encapsulated `WSMessageReceive` payloads
  - Outgoing encapsulated `WSMessageSend` payloads
  - Presence Updates
  - Read Receipts
  - Typing Indicators

## Media & Files API (`/files`)

Handled by the **File Service**. Operates on the premise that files are pre-encrypted client-side.

### Secure File Transfer
- `POST /files/upload`: Securely upload an encrypted chunk stream of data. Returns a metadata UUID object.
- `GET /files/{id}`: Download a previously uploaded encrypted file blob.
- `GET /files/{id}/info`: Query the system for encrypted file metadata prior to download mapping.
