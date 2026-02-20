# Build stage
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build all services
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /api-gateway ./cmd/api-gateway
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /auth-service ./cmd/auth-service
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /key-service ./cmd/key-service
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /message-service ./cmd/message-service
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /file-service ./cmd/file-service

# Runtime stage
FROM alpine:3.19

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy binaries from builder
COPY --from=builder /api-gateway /auth-service /key-service /message-service /file-service ./
COPY --from=builder /app/config.yaml ./

# Create non-root user
RUN addgroup -g 1000 appgroup && \
    adduser -u 1000 -G appgroup -D appuser && \
    chown -R appuser:appgroup /app

USER appuser

# Default command (can be overridden)
ENTRYPOINT ["./api-gateway"]
