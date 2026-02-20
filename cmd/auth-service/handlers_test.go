package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/secure-messenger/internal/config"
	"github.com/secure-messenger/internal/database"
)

// setupTestDB creates a test database connection and auth service instance
func setupTestDB(t *testing.T) (*AuthService, func()) {
	// We need a real DB connection or a mock. Since the codebase uses pgxpool directly,
	// let's try to connect to the DB specified in env vars or fallback to a default test DB.

	// For the sake of this test, we might skip if no DB is available,
	// but let's try to set it up.

	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Host:            "localhost",
			Port:            5432,
			User:            "postgres",
			Password:        "password",
			Database:        "secure_messenger_test",
			SSLMode:         "disable",
			MaxOpenConns:    10,
			MaxIdleConns:    5,
			ConnMaxLifetime: time.Hour,
		},
		JWT: config.JWTConfig{
			AccessTokenSecret:  "secret1",
			RefreshTokenSecret: "secret2",
			AccessTokenExpiry:  15 * time.Minute,
			RefreshTokenExpiry: 24 * time.Hour,
			Issuer:             "test",
		},
	}

	// cfg.applyEnvOverrides() // allow overriding for CI

	db, err := database.New(&cfg.Database)
	if err != nil {
		t.Skipf("Skipping DB tests: failed to connect to test DB: %v", err)
	}

	// Run migrations
	if err := db.Migrate(context.Background()); err != nil {
		db.Close()
		t.Fatalf("Failed to run migrations: %v", err)
	}

	// Clean up users table before tests
	db.Pool().Exec(context.Background(), "DELETE FROM users")

	service := &AuthService{
		config:   cfg,
		db:       db,
		userRepo: database.NewUserRepository(db),
	}

	cleanup := func() {
		db.Pool().Exec(context.Background(), "DELETE FROM users")
		db.Close()
	}

	return service, cleanup
}

func TestRegisterAndLogin(t *testing.T) {
	service, cleanup := setupTestDB(t)
	if service == nil {
		return // Skipped
	}
	defer cleanup()

	// 1. Test Registration
	registerReq := RegisterRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
	}

	body, _ := json.Marshal(registerReq)
	req := httptest.NewRequest("POST", "/api/v1/auth/register", bytes.NewReader(body))
	w := httptest.NewRecorder()

	service.Register(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status OK for register, got %d. Body: %s", w.Code, w.Body.String())
	}

	var registerResp AuthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &registerResp); err != nil {
		t.Fatalf("Failed to parse register response: %v", err)
	}

	if registerResp.AccessToken == "" {
		t.Error("Expected access token in register response")
	}

	// 2. Test Login
	loginReq := LoginRequest{
		Username: "testuser",
		Password: "password123",
	}

	body, _ = json.Marshal(loginReq)
	req = httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(body))
	w = httptest.NewRecorder()

	service.Login(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status OK for login, got %d. Body: %s", w.Code, w.Body.String())
	}

	var loginResp AuthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &loginResp); err != nil {
		t.Fatalf("Failed to parse login response: %v", err)
	}

	if loginResp.AccessToken == "" {
		t.Error("Expected access token in login response")
	}
}

func TestRegisterValidation(t *testing.T) {
	service, cleanup := setupTestDB(t)
	if service == nil {
		return // Skipped
	}
	defer cleanup()

	tests := []struct {
		name       string
		req        RegisterRequest
		statusCode int
	}{
		{
			name: "Missing Username",
			req: RegisterRequest{
				Email:    "test@example.com",
				Password: "password123",
			},
			statusCode: http.StatusBadRequest,
		},
		{
			name: "Short Password",
			req: RegisterRequest{
				Username: "testuser2",
				Email:    "test2@example.com",
				Password: "short",
			},
			statusCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.req)
			req := httptest.NewRequest("POST", "/api/v1/auth/register", bytes.NewReader(body))
			w := httptest.NewRecorder()

			service.Register(w, req)

			if w.Code != tt.statusCode {
				t.Errorf("Expected status %d, got %d", tt.statusCode, w.Code)
			}
		})
	}
}
