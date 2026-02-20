# Secure Messenger - Backend

A secure messenger backend with end-to-end encryption, built in Go for Ubuntu Server.

## Features

- **End-to-End Encryption**: Full E2E encryption using Signal Protocol (X25519, Ed25519, AES-256-GCM)
- **Microservices Architecture**: Scalable and maintainable service-oriented design
- **Real-time Messaging**: WebSocket-based instant message delivery
- **File Sharing**: Encrypted file transfer up to 100MB
- **Group Chats**: Support for group conversations with up to 200 members

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      API Gateway (:8080)                     │
│                   (Routing, Rate Limiting)                   │
└─────────────────────┬───────────────────────────────────────┘
                      │
    ┌─────────────────┼─────────────────┬─────────────────────┐
    │                 │                 │                     │
    ▼                 ▼                 ▼                     ▼
┌────────┐     ┌──────────┐     ┌──────────┐          ┌──────────┐
│  Auth  │     │   Key    │     │ Message  │          │   File   │
│Service │     │ Service  │     │ Service  │          │ Service  │
│ :8081  │     │  :8084   │     │  :8082   │          │  :8083   │
└───┬────┘     └────┬─────┘     └────┬─────┘          └────┬─────┘
    │               │                │                     │
    └───────────────┴────────────────┴─────────────────────┘
                           │
    ┌──────────────────────┼──────────────────────────────┐
    │                      │                              │
    ▼                      ▼                              ▼
┌────────┐          ┌──────────┐                   ┌──────────┐
│Postgres│          │   NATS   │                   │  MinIO   │
│   16   │          │ JetStream│                   │  S3-like │
└────────┘          └──────────┘                   └──────────┘
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| API Gateway | 8080 | Entry point, routing, rate limiting |
| Auth Service | 8081 | Authentication, JWT tokens |
| Key Service | 8084 | Cryptographic key management |
| Message Service | 8082 | Real-time messaging, WebSocket |
| File Service | 8083 | Encrypted file storage |

## Quick Start

### Prerequisites

- Go 1.22+
- Docker & Docker Compose
- Make (optional)

### Using Docker Compose

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Local Development

```bash
# Install dependencies
go mod download

# Start infrastructure
docker-compose up -d postgres redis nats minio

# Run migrations (automatic on first start)

# Start services
go run ./cmd/auth-service &
go run ./cmd/key-service &
go run ./cmd/message-service &
go run ./cmd/file-service &
go run ./cmd/api-gateway
```

## API Endpoints

### Authentication (`/api/v1/auth`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /register | Register new user |
| POST | /login | Authenticate user |
| POST | /refresh | Refresh access token |
| POST | /logout | Invalidate session |

### Keys (`/api/v1/keys`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /identity | Upload identity key |
| GET | /identity/{user_id} | Get user's identity key |
| POST | /signed-prekey | Upload signed prekey |
| GET | /bundle/{user_id} | Get prekey bundle for X3DH |
| POST | /one-time-prekeys | Upload one-time prekeys |

### Messages (`/api/v1`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /conversations | Create conversation |
| GET | /conversations/{id}/messages | Get message history |
| WS | /ws | WebSocket connection |

### Files (`/api/v1/files`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /upload | Upload encrypted file |
| GET | /{id} | Download file |
| GET | /{id}/info | Get file metadata |

## Cryptographic Protocol

The messenger implements Signal Protocol for E2E encryption:

1. **X3DH Key Exchange**: Initial session establishment
2. **Double Ratchet**: Ongoing message encryption with forward secrecy
3. **AES-256-GCM**: Symmetric encryption for messages
4. **Ed25519**: Digital signatures for authentication
5. **X25519**: Diffie-Hellman key agreement

### Key Hierarchy

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
            └── Chain Key → Message Keys (AES-256-GCM)
```

## Configuration

Configuration is managed via `config.yaml` and environment variables:

```yaml
server:
  port: 8080

database:
  host: localhost
  port: 5432
  user: messenger
  password: messenger_secret
  database: messenger_db

jwt:
  access_token_secret: your-secret-key
  refresh_token_secret: your-refresh-secret
  access_token_expiry: 15m
  refresh_token_expiry: 720h
```

Environment variables override YAML settings:
- `SERVER_PORT`
- `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`
- `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`

## Database Schema

The PostgreSQL database contains the following main tables:

- `users` - User accounts
- `identity_keys` - Long-term identity keys
- `signed_prekeys` - Signed prekeys for X3DH
- `one_time_prekeys` - One-time prekeys
- `conversations` - Chat rooms
- `conversation_members` - Membership relations
- `messages` - Encrypted messages
- `files` - File metadata

## Security Considerations

1. **Zero-Knowledge Server**: All encryption happens client-side
2. **Forward Secrecy**: Compromised keys don't expose past messages
3. **Key Rotation**: Automatic key rotation with Double Ratchet
4. **No Plaintext Storage**: Messages and files stored encrypted
5. **Token-Based Auth**: JWT with short-lived access tokens

## Deployment

### Kubernetes

Kubernetes manifests are available in `deployments/k8s/`:

```bash
kubectl apply -f deployments/k8s/
```

### Production Checklist

- [ ] Change all default secrets
- [ ] Enable TLS/SSL
- [ ] Configure rate limiting
- [ ] Set up monitoring (Prometheus/Grafana)
- [ ] Configure log aggregation
- [ ] Enable PostgreSQL SSL
- [ ] Set up database backups
- [ ] Configure MinIO replication

## Development

### Project Structure

```
secure-messenger/
├── cmd/                    # Service entry points
│   ├── api-gateway/
│   ├── auth-service/
│   ├── key-service/
│   ├── message-service/
│   └── file-service/
├── internal/               # Private packages
│   ├── config/
│   ├── crypto/
│   ├── database/
│   ├── middleware/
│   ├── models/
│   └── protocol/
├── pkg/                    # Public packages
├── deployments/            # Deployment configs
│   ├── docker/
│   └── k8s/
└── scripts/               # Utility scripts
```

### Running Tests

```bash
go test ./... -v
```

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request
