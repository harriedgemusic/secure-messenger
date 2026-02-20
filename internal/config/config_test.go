package config

import (
	"os"
	"testing"
)

func TestApplyEnvOverrides(t *testing.T) {
	// Setup initial config
	cfg := &Config{
		Server: ServerConfig{
			Host: "localhost",
			Port: 8080,
		},
		Database: DatabaseConfig{
			Host: "127.0.0.1",
			Port: 5432,
		},
		JWT: JWTConfig{
			AccessTokenSecret: "old_secret",
		},
	}

	// Set environment variables
	os.Setenv("SERVER_HOST", "0.0.0.0")
	os.Setenv("SERVER_PORT", "9090")
	os.Setenv("DB_HOST", "db.internal")
	os.Setenv("DB_PORT", "5433")
	os.Setenv("DB_USER", "admin")
	os.Setenv("DB_PASSWORD", "secret_db")
	os.Setenv("DB_NAME", "messagedb")
	os.Setenv("JWT_ACCESS_SECRET", "new_secret1")
	os.Setenv("JWT_REFRESH_SECRET", "new_secret2")

	defer func() {
		// Clean up
		os.Unsetenv("SERVER_HOST")
		os.Unsetenv("SERVER_PORT")
		os.Unsetenv("DB_HOST")
		os.Unsetenv("DB_PORT")
		os.Unsetenv("DB_USER")
		os.Unsetenv("DB_PASSWORD")
		os.Unsetenv("DB_NAME")
		os.Unsetenv("JWT_ACCESS_SECRET")
		os.Unsetenv("JWT_REFRESH_SECRET")
	}()

	// Apply overrides
	cfg.applyEnvOverrides()

	// Verify server config
	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("Expected SERVER_HOST '0.0.0.0', got %q", cfg.Server.Host)
	}
	if cfg.Server.Port != 9090 {
		t.Errorf("Expected SERVER_PORT 9090, got %d", cfg.Server.Port)
	}

	// Verify DB config
	if cfg.Database.Host != "db.internal" {
		t.Errorf("Expected DB_HOST 'db.internal', got %q", cfg.Database.Host)
	}
	if cfg.Database.Port != 5433 {
		t.Errorf("Expected DB_PORT 5433, got %d", cfg.Database.Port)
	}
	if cfg.Database.User != "admin" {
		t.Errorf("Expected DB_USER 'admin', got %q", cfg.Database.User)
	}
	if cfg.Database.Password != "secret_db" {
		t.Errorf("Expected DB_PASSWORD 'secret_db', got %q", cfg.Database.Password)
	}
	if cfg.Database.Database != "messagedb" {
		t.Errorf("Expected DB_NAME 'messagedb', got %q", cfg.Database.Database)
	}

	// Verify JWT config
	if cfg.JWT.AccessTokenSecret != "new_secret1" {
		t.Errorf("Expected JWT_ACCESS_SECRET 'new_secret1', got %q", cfg.JWT.AccessTokenSecret)
	}
	if cfg.JWT.RefreshTokenSecret != "new_secret2" {
		t.Errorf("Expected JWT_REFRESH_SECRET 'new_secret2', got %q", cfg.JWT.RefreshTokenSecret)
	}
}

func TestDSNGeneration(t *testing.T) {
	cfg := &DatabaseConfig{
		Host:     "localhost",
		Port:     5432,
		User:     "user",
		Password: "password",
		Database: "dbname",
		SSLMode:  "disable",
	}

	expected := "postgres://user:password@localhost:5432/dbname?sslmode=disable"
	actual := cfg.DSN()

	if actual != expected {
		t.Errorf("Expected DSN %q, got %q", expected, actual)
	}
}

func TestRedisGeneration(t *testing.T) {
	cfg := &RedisConfig{
		Host: "redis",
		Port: 6379,
	}

	expected := "redis:6379"
	actual := cfg.Addr()

	if actual != expected {
		t.Errorf("Expected Addr %q, got %q", expected, actual)
	}
}

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file
	data := []byte(`
server:
  host: "127.0.0.1"
  port: 8080
database:
  host: "localhost"
  port: 5432
`)
	f, err := os.CreateTemp("", "config_test.yaml")
	if err != nil {
		t.Fatalf("Failed to create temporary config file: %v", err)
	}
	defer os.Remove(f.Name())

	if _, err := f.Write(data); err != nil {
		t.Fatalf("Failed to write to temporary config file: %v", err)
	}
	f.Close()

	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Server.Port != 8080 {
		t.Errorf("Expected port 8080, got %d", cfg.Server.Port)
	}
	if cfg.Database.Host != "localhost" {
		t.Errorf("Expected DB host 'localhost', got %q", cfg.Database.Host)
	}
}

func TestLoadConfigError(t *testing.T) {
	_, err := Load("non_existent_file.yaml")
	if err == nil {
		t.Error("expected error loading non existent file")
	}

	// create invalid yaml
	f, _ := os.CreateTemp("", "invalid.yaml")
	defer os.Remove(f.Name())
	f.Write([]byte("invalid: yaml: content:"))
	f.Close()

	_, err = Load(f.Name())
	if err == nil {
		t.Error("expected error loading invalid yaml")
	}
}
