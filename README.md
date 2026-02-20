# Secure Messenger - Backend

A highly secure messenger backend implementing end-to-end encryption with Zero-Knowledge Architecture, built in Go for Ubuntu Server.

## Key Features

- **End-to-End Encryption**: Robust E2E encryption integrating the Signal Protocol guidelines (X3DH, Double Ratchet, X25519, Ed25519, AES-256-GCM).
- **Scalable Microservices Architecture**: Decoupled, maintainable service-oriented design containerized for peak performance.
- **Real-time Messaging**: High-availability WebSocket-based instant message delivery scaling horizontally with NATS JetStream.
- **Secure File Sharing**: Fully encrypted file transfer scaling up to 100MB object sizes mapping to MinIO.
- **Group Chats**: Strong P2P and Group chats supporting up to 200 members per room.

## Project Documentation

Detailed system specifications are located in the `documentation/` directory:
- [Architecture & System Overview](documentation/architecture.md)
- [API Specifications & Authentication](documentation/api.md)
- [Cryptographic Protocol Implementation](documentation/crypto.md)
- [Database Schema structure](documentation/database.md)

## Microservices Catalog

| Service | Port | Description |
|---------|------|-------------|
| API Gateway | 8080 | Entry point, HTTP/WS routing, rate limiting |
| Auth Service | 8081 | Identity management, Session JWT tokens (Argon2id hashes) |
| Key Service | 8084 | Cryptographic public key repository handling |
| Message Service | 8082 | Event-driven real-time messaging, WebSocket persistence |
| File Service | 8083 | Encrypted object file storage linked to MinIO |

---

## 🚀 Complete Ubuntu Server Deployment Guide

The following instructions comprehensively walk through deploying the Secure Messenger to an **Ubuntu Server (24.04 LTS or newer)** entirely from scratch using Docker Compose.

### Step 1: System Preparation and Updates
First, ensure your base Ubuntu packages are fully up-to-date and install the required core utilities.
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl git jq openssl
```

### Step 2: Install Docker & Docker Compose
The entire microservice ecosystem relies heavily on container orchestration via Docker. Install the latest engine directly from Docker's official script.
```bash
# Fetch and run the official Docker installation script
curl -fsSL https://get.docker.com | sh

# Add your current user to the docker group to avoid requiring 'sudo'
sudo usermod -aG docker $USER

# Apply the group change directly to your current shell session
newgrp docker

# Verify the installation was successful
docker --version
docker compose version
```

### Step 3: Clone the Repository
Pull the secure-messenger source code to your target deployment directory (e.g., your home folder or `/opt/`).
```bash
git clone https://github.com/harriedgemusic/secure-messenger.git
cd secure-messenger
```

### Step 4: Configure Environment Variables
You must securely generate the secret keys, passwords, and tokens required by PostgreSQL, MinIO, and the Auth Service (JWT). Run the following block to auto-generate a `.env` file populated with cryptographically secure random values:

```bash
cat > .env << EOF
# Auto-generated secrets
DB_PASSWORD=$(openssl rand -base64 32 | tr -d '/+=' | head -c 32)
JWT_ACCESS_SECRET=$(openssl rand -base64 48 | tr -d '/+=' | head -c 64)
JWT_REFRESH_SECRET=$(openssl rand -base64 48 | tr -d '/+=' | head -c 64)
MINIO_ROOT_PASSWORD=$(openssl rand -base64 24 | tr -d '/+=' | head -c 24)
EOF

# Ensure appropriate read-write limits are kept tight
chmod 600 .env
```
*(Optional) Review the generated secrets using `cat .env` before proceeding.*

### Step 5: Bootstrapping and Launch
With secrets generated, invoke Docker Compose to download images, build the Go microservices locally, and establish the custom networks & volumes.
```bash
# Build and dynamically spawn all containers in detached mode
docker compose up -d --build
```
This deploys:
- PostgreSQL 16 (Relational schemas automatically migrating on boot)
- Redis (Session Caching layer)
- NATS JetStream (Pub/Sub message broker)
- MinIO (Local encrypted object file store)
- `api-gateway`, `auth-service`, `key-service`, `message-service`, `file-service`

### Step 6: Verify Deployment and Health Status
Double check that all dependent services are `running` without restarting cycles.
```bash
docker compose ps
```
Ping the API Gateway's healthcheck endpoint:
```bash
curl http://localhost:8080/health
# Expected Output format: {"status":"healthy","timestamp":"..."}
```

### Step 7: Test E2E Operability
Create a test user account to confirm your database, gateway routing, and authentication service are fully integrated:
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "SuperSecretPassword123!"
  }'
```

### Service Management Cheat Sheet
- **View all Application Logs:** `docker compose logs -f`
- **View specific Service Logs (e.g. gateway):** `docker compose logs -f api-gateway`
- **Restart the whole stack:** `docker compose restart`
- **Stop services and remove containers (Keep Volumes):** `docker compose down`
- **Nuke Everything (Containers, Networks, and VOLUMES/DATA):** `docker compose down -v`

---

## License

MIT License - see LICENSE file for details.
