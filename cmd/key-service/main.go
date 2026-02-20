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

	"github.com/gorilla/mux"
	"github.com/secure-messenger/internal/config"
	"github.com/secure-messenger/internal/database"
	"github.com/secure-messenger/internal/middleware"
	"github.com/secure-messenger/internal/models"
)

type KeyService struct {
	config  *config.Config
	db      *database.Database
	keyRepo *database.KeyRepository
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

	service := &KeyService{
		config:  cfg,
		db:      db,
		keyRepo: database.NewKeyRepository(db),
	}

	router := mux.NewRouter()
	router.Use(middleware.LoggingMiddleware)
	router.Use(middleware.RecoveryMiddleware)
	router.Use(middleware.CORSMiddleware([]string{"*"}))

	// All routes require authentication
	api := router.PathPrefix("/api/v1").Subrouter()
	api.Use(middleware.AuthMiddleware(&cfg.JWT))

	// Identity keys
	api.HandleFunc("/keys/identity", service.UploadIdentityKey).Methods("POST")
	api.HandleFunc("/keys/identity/{user_id}", service.GetIdentityKey).Methods("GET")

	// Signed prekeys
	api.HandleFunc("/keys/signed-prekey", service.UploadSignedPreKey).Methods("POST")
	api.HandleFunc("/keys/signed-prekey/{user_id}", service.GetSignedPreKey).Methods("GET")

	// One-time prekeys
	api.HandleFunc("/keys/one-time-prekeys", service.UploadOneTimePreKeys).Methods("POST")
	api.HandleFunc("/keys/one-time-prekeys/{user_id}", service.GetOneTimePreKey).Methods("GET")

	// Prekey bundle (for X3DH)
	api.HandleFunc("/keys/bundle/{user_id}", service.GetPreKeyBundle).Methods("GET")

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	go func() {
		log.Printf("Key Service starting on port %d", cfg.Server.Port)
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
	log.Println("Key Service stopped")
}

type UploadIdentityKeyRequest struct {
	PublicKey []byte `json:"public_key"`
	Signature []byte `json:"signature"`
}

type UploadSignedPreKeyRequest struct {
	KeyID     uint32 `json:"key_id"`
	PublicKey []byte `json:"public_key"`
	Signature []byte `json:"signature"`
}

type UploadOneTimePreKeysRequest struct {
	Keys []OneTimePreKeyItem `json:"keys"`
}

type OneTimePreKeyItem struct {
	KeyID     uint32 `json:"key_id"`
	PublicKey []byte `json:"public_key"`
}

func (s *KeyService) UploadIdentityKey(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		sendError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req UploadIdentityKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.PublicKey) != 32 {
		sendError(w, http.StatusBadRequest, "invalid public key size")
		return
	}

	ik := &models.IdentityKey{
		UserID:    userID,
		PublicKey: req.PublicKey,
		Signature: req.Signature,
	}

	if err := s.keyRepo.StoreIdentityKey(r.Context(), ik); err != nil {
		sendError(w, http.StatusInternalServerError, "failed to store identity key")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{
		Status:  "success",
		Message: "identity key stored",
	})
}

func (s *KeyService) GetIdentityKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["user_id"]

	ik, err := s.keyRepo.GetIdentityKey(r.Context(), userID)
	if err != nil {
		sendError(w, http.StatusNotFound, "identity key not found")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{
		Status: "success",
		Data: map[string]interface{}{
			"user_id":    ik.UserID,
			"public_key": ik.PublicKey,
			"signature":  ik.Signature,
			"created_at": ik.CreatedAt,
		},
	})
}

func (s *KeyService) UploadSignedPreKey(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		sendError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req UploadSignedPreKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.PublicKey) != 32 {
		sendError(w, http.StatusBadRequest, "invalid public key size")
		return
	}

	spk := &models.SignedPreKey{
		UserID:    userID,
		KeyID:     req.KeyID,
		PublicKey: req.PublicKey,
		Signature: req.Signature,
	}

	if err := s.keyRepo.StoreSignedPreKey(r.Context(), spk); err != nil {
		sendError(w, http.StatusInternalServerError, "failed to store signed prekey")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{
		Status:  "success",
		Message: "signed prekey stored",
	})
}

func (s *KeyService) GetSignedPreKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["user_id"]

	spk, err := s.keyRepo.GetSignedPreKey(r.Context(), userID)
	if err != nil {
		sendError(w, http.StatusNotFound, "signed prekey not found")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{
		Status: "success",
		Data: map[string]interface{}{
			"user_id":    spk.UserID,
			"key_id":     spk.KeyID,
			"public_key": spk.PublicKey,
			"signature":  spk.Signature,
			"created_at": spk.CreatedAt,
		},
	})
}

func (s *KeyService) UploadOneTimePreKeys(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		sendError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req UploadOneTimePreKeysRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Keys) == 0 {
		sendError(w, http.StatusBadRequest, "no keys provided")
		return
	}

	otpks := make([]*models.OneTimePreKey, len(req.Keys))
	for i, key := range req.Keys {
		otpks[i] = &models.OneTimePreKey{
			UserID:    userID,
			KeyID:     key.KeyID,
			PublicKey: key.PublicKey,
			Used:      false,
		}
	}

	if err := s.keyRepo.StoreOneTimePreKeys(r.Context(), otpks); err != nil {
		sendError(w, http.StatusInternalServerError, "failed to store one-time prekeys")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{
		Status:  "success",
		Message: fmt.Sprintf("%d one-time prekeys stored", len(req.Keys)),
	})
}

func (s *KeyService) GetOneTimePreKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["user_id"]

	otpk, err := s.keyRepo.GetOneTimePreKey(r.Context(), userID)
	if err != nil {
		sendError(w, http.StatusNotFound, "no available one-time prekeys")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{
		Status: "success",
		Data: map[string]interface{}{
			"key_id":     otpk.KeyID,
			"public_key": otpk.PublicKey,
		},
	})
}

func (s *KeyService) GetPreKeyBundle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["user_id"]

	bundle, err := s.keyRepo.GetPreKeyBundle(r.Context(), userID)
	if err != nil {
		sendError(w, http.StatusNotFound, "prekey bundle not found")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{
		Status: "success",
		Data:   bundle,
	})
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
