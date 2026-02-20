package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/secure-messenger/internal/config"
	"github.com/secure-messenger/internal/crypto"
	"github.com/secure-messenger/internal/database"
	"github.com/secure-messenger/internal/middleware"
	"github.com/secure-messenger/internal/models"
)

type AuthService struct {
	config     *config.Config
	db         *database.Database
	userRepo   *database.UserRepository
}

func main() {
	cfg, err := config.Load("config.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	db, err := database.New(&cfg.Database)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	if err := db.Migrate(context.Background()); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	service := &AuthService{
		config:   cfg,
		db:       db,
		userRepo: database.NewUserRepository(db),
	}

	router := mux.NewRouter()
	router.Use(middleware.LoggingMiddleware)
	router.Use(middleware.RecoveryMiddleware)
	router.Use(middleware.CORSMiddleware([]string{"*"}))

	// Public routes
	router.HandleFunc("/api/v1/auth/register", service.Register).Methods("POST")
	router.HandleFunc("/api/v1/auth/login", service.Login).Methods("POST")
	router.HandleFunc("/api/v1/auth/refresh", service.RefreshToken).Methods("POST")

	// Protected routes
	protected := router.PathPrefix("/api/v1").Subrouter()
	protected.Use(middleware.AuthMiddleware(&cfg.JWT))
	protected.HandleFunc("/auth/logout", service.Logout).Methods("POST")
	protected.HandleFunc("/auth/me", service.GetCurrentUser).Methods("GET")
	protected.HandleFunc("/users/{id}", service.GetUser).Methods("GET")

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	go func() {
		log.Printf("Auth Service starting on port %d", cfg.Server.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server shutdown error: %v", err)
	}
	log.Println("Auth Service stopped")
}

type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	User         struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
	} `json:"user"`
}

func (s *AuthService) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Username == "" || req.Email == "" || req.Password == "" {
		sendError(w, http.StatusBadRequest, "username, email and password are required")
		return
	}

	if len(req.Password) < 8 {
		sendError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}

	// Check if user exists
	if _, err := s.userRepo.GetByUsername(r.Context(), req.Username); err == nil {
		sendError(w, http.StatusConflict, "username already exists")
		return
	}

	if _, err := s.userRepo.GetByEmail(r.Context(), req.Email); err == nil {
		sendError(w, http.StatusConflict, "email already exists")
		return
	}

	// Hash password
	passwordHash, err := crypto.PasswordHash(req.Password, nil)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	// Create user
	user := &models.User{
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: passwordHash,
		IsActive:     true,
	}

	if err := s.userRepo.Create(r.Context(), user); err != nil {
		sendError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	// Generate tokens
	accessToken, err := s.generateAccessToken(user.ID)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "failed to generate access token")
		return
	}

	refreshToken, err := s.generateRefreshToken(user.ID)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "failed to generate refresh token")
		return
	}

	sendAuthResponse(w, accessToken, refreshToken, user)
}

func (s *AuthService) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Username == "" || req.Password == "" {
		sendError(w, http.StatusBadRequest, "username and password are required")
		return
	}

	// Get user
	user, err := s.userRepo.GetByUsername(r.Context(), req.Username)
	if err != nil {
		sendError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if !user.IsActive {
		sendError(w, http.StatusForbidden, "account is disabled")
		return
	}

	// Verify password
	valid, err := crypto.VerifyPassword(req.Password, user.PasswordHash)
	if err != nil || !valid {
		sendError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Generate tokens
	accessToken, err := s.generateAccessToken(user.ID)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "failed to generate access token")
		return
	}

	refreshToken, err := s.generateRefreshToken(user.ID)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "failed to generate refresh token")
		return
	}

	sendAuthResponse(w, accessToken, refreshToken, user)
}

func (s *AuthService) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	token, err := jwt.Parse(req.RefreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(s.config.JWT.RefreshTokenSecret), nil
	})

	if err != nil || !token.Valid {
		sendError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		sendError(w, http.StatusUnauthorized, "invalid token claims")
		return
	}

	userID, ok := claims["sub"].(string)
	if !ok {
		sendError(w, http.StatusUnauthorized, "invalid user id in token")
		return
	}

	user, err := s.userRepo.GetByID(r.Context(), userID)
	if err != nil {
		sendError(w, http.StatusUnauthorized, "user not found")
		return
	}

	if !user.IsActive {
		sendError(w, http.StatusForbidden, "account is disabled")
		return
	}

	accessToken, err := s.generateAccessToken(user.ID)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "failed to generate access token")
		return
	}

	newRefreshToken, err := s.generateRefreshToken(user.ID)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "failed to generate refresh token")
		return
	}

	sendAuthResponse(w, accessToken, newRefreshToken, user)
}

func (s *AuthService) Logout(w http.ResponseWriter, r *http.Request) {
	// In a production system, you would invalidate the refresh token
	w.WriteHeader(http.StatusNoContent)
}

func (s *AuthService) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		sendError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	user, err := s.userRepo.GetByID(r.Context(), userID)
	if err != nil {
		sendError(w, http.StatusNotFound, "user not found")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{
		Status: "success",
		Data: map[string]interface{}{
			"id":       user.ID,
			"username": user.Username,
			"email":    user.Email,
		},
	})
}

func (s *AuthService) GetUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]

	user, err := s.userRepo.GetByID(r.Context(), userID)
	if err != nil {
		sendError(w, http.StatusNotFound, "user not found")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{
		Status: "success",
		Data: map[string]interface{}{
			"id":       user.ID,
			"username": user.Username,
		},
	})
}

func (s *AuthService) generateAccessToken(userID string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": userID,
		"iat": now.Unix(),
		"exp": now.Add(s.config.JWT.AccessTokenExpiry).Unix(),
		"iss": s.config.JWT.Issuer,
		"jti": uuid.New().String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.JWT.AccessTokenSecret))
}

func (s *AuthService) generateRefreshToken(userID string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": userID,
		"iat": now.Unix(),
		"exp": now.Add(s.config.JWT.RefreshTokenExpiry).Unix(),
		"iss": s.config.JWT.Issuer,
		"jti": uuid.New().String(),
		"type": "refresh",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.JWT.RefreshTokenSecret))
}

func sendAuthResponse(w http.ResponseWriter, accessToken, refreshToken string, user *models.User) {
	resp := AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(15 * 60), // 15 minutes
	}
	resp.User.ID = user.ID
	resp.User.Username = user.Username
	resp.User.Email = user.Email

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func sendError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(models.ErrorResponse{
		Error:   http.StatusText(status),
		Code:    status,
		Message: message,
	})
}
