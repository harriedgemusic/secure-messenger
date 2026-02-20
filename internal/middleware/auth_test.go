package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/secure-messenger/internal/config"
)

func TestAuthMiddleware(t *testing.T) {
	jwtCfg := &config.JWTConfig{
		AccessTokenSecret: "supersecret",
		AccessTokenExpiry: time.Hour,
		Issuer:            "test-issuer",
	}

	middleware := AuthMiddleware(jwtCfg)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := GetUserID(r.Context())
		if userID != "test-user-id" {
			t.Errorf("Expected userID 'test-user-id', got %q", userID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("ValidToken", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub": "test-user-id",
			"iss": "test-issuer",
			"exp": time.Now().Add(time.Hour).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte("supersecret"))
		if err != nil {
			t.Fatalf("Failed to sign token: %v", err)
		}

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status OK, got %d", w.Code)
		}
	})

	t.Run("MissingToken", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status Unauthorized, got %d", w.Code)
		}
	})

	t.Run("InvalidFormat", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "InvalidFormat token")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status Unauthorized, got %d", w.Code)
		}
	})

	t.Run("InvalidToken", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer invalidtoken")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status Unauthorized, got %d", w.Code)
		}
	})

	t.Run("ExpiredToken", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub": "test-user-id",
			"iss": "test-issuer",
			"exp": time.Now().Add(-time.Hour).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte("supersecret"))
		if err != nil {
			t.Fatalf("Failed to sign token: %v", err)
		}

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status Unauthorized, got %d", w.Code)
		}
	})
}

func TestGetUserID(t *testing.T) {
	ctx := context.WithValue(context.Background(), UserIDKey, "user-123")
	userID := GetUserID(ctx)
	if userID != "user-123" {
		t.Errorf("Expected 'user-123', got %q", userID)
	}

	emptyCtx := context.Background()
	emptyID := GetUserID(emptyCtx)
	if emptyID != "" {
		t.Errorf("Expected empty string, got %q", emptyID)
	}
}

func TestCORSMiddleware(t *testing.T) {
	middleware := CORSMiddleware([]string{"http://example.com"})

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("AllowedOrigin", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Origin", "http://example.com")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status OK, got %d", w.Code)
		}
		if w.Header().Get("Access-Control-Allow-Origin") != "http://example.com" {
			t.Errorf("Expected CORS header")
		}
	})

	t.Run("OptionsRequest", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/", nil)
		req.Header.Set("Origin", "http://example.com")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status OK, got %d", w.Code)
		}
		// Method should not be passed to next handler, just returns 200 OK directly from middleware
	})
}

func TestRateLimitMiddleware(t *testing.T) {
	middleware := RateLimitMiddleware(10)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status OK, got %d", w.Code)
	}
}

func TestLoggingMiddleware(t *testing.T) {
	handler := LoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status OK, got %d", w.Code)
	}
}

func TestRecoveryMiddleware(t *testing.T) {
	handler := RecoveryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status InternalServerError after panic, got %d", w.Code)
	}
}
