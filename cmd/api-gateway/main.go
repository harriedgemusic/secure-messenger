package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/secure-messenger/internal/config"
	"github.com/secure-messenger/internal/middleware"
)

type APIGateway struct {
	config     *config.Config
	services   map[string]string
}

func main() {
	cfg, err := config.Load("config.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	gateway := &APIGateway{
		config: cfg,
		services: map[string]string{
			"auth":    "http://localhost:8081",
			"key":     "http://localhost:8084",
			"message": "http://localhost:8082",
			"file":    "http://localhost:8083",
		},
	}

	router := mux.NewRouter()
	router.Use(middleware.LoggingMiddleware)
	router.Use(middleware.RecoveryMiddleware)
	router.Use(middleware.CORSMiddleware([]string{"*"}))

	// Health check
	router.HandleFunc("/health", gateway.HealthCheck).Methods("GET")

	// Route to services
	router.PathPrefix("/api/v1/auth").Handler(gateway.proxy("auth"))
	router.PathPrefix("/api/v1/keys").Handler(gateway.proxy("key"))
	router.PathPrefix("/api/v1/conversations").Handler(gateway.proxy("message"))
	router.PathPrefix("/api/v1/messages").Handler(gateway.proxy("message"))
	router.PathPrefix("/api/v1/files").Handler(gateway.proxy("file"))
	router.PathPrefix("/api/v1/users").Handler(gateway.proxy("auth"))

	// WebSocket proxy
	router.PathPrefix("/ws").Handler(gateway.websocketProxy())

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	go func() {
		log.Printf("API Gateway starting on port %d", cfg.Server.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server shutdown error: %v", err)
	}
	log.Println("API Gateway stopped")
}

func (g *APIGateway) proxy(service string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target, ok := g.services[service]
		if !ok {
			http.Error(w, "service not found", http.StatusBadGateway)
			return
		}

		targetURL, err := url.Parse(target)
		if err != nil {
			http.Error(w, "invalid service URL", http.StatusInternalServerError)
			return
		}

		proxy := httputil.NewSingleHostReverseProxy(targetURL)
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("Proxy error: %v", err)
			http.Error(w, "service unavailable", http.StatusBadGateway)
		}

		proxy.ServeHTTP(w, r)
	})
}

func (g *APIGateway) websocketProxy() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := g.services["message"]
		targetURL, err := url.Parse(target)
		if err != nil {
			http.Error(w, "invalid service URL", http.StatusInternalServerError)
			return
		}

		// WebSocket requires special handling
		r.URL.Scheme = "ws"
		r.URL.Host = targetURL.Host

		proxy := httputil.NewSingleHostReverseProxy(targetURL)
		proxy.Transport = &websocketTransport{}
		proxy.ServeHTTP(w, r)
	})
}

type websocketTransport struct{}

func (t *websocketTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	// Upgrade connection for WebSocket
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "websocket")
	return http.DefaultTransport.RoundTrip(r)
}

func (g *APIGateway) HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"healthy","timestamp":"%s"}`, time.Now().Format(time.RFC3339))
}

// Helper to strip path prefix for proxying
func stripPrefix(prefix string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, prefix) {
			r.URL.Path = strings.TrimPrefix(r.URL.Path, prefix)
			if r.URL.Path == "" {
				r.URL.Path = "/"
			}
		}
		h.ServeHTTP(w, r)
	})
}
