package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/secure-messenger/internal/config"
	"github.com/secure-messenger/internal/database"
	"github.com/secure-messenger/internal/middleware"
	"github.com/secure-messenger/internal/models"
)

const (
	MaxFileSize = 100 * 1024 * 1024 // 100 MB
	ChunkSize   = 5 * 1024 * 1024   // 5 MB
)

type FileService struct {
	config    *config.Config
	db        *database.Database
	fileRepo  *database.FileRepository
	minio     *minio.Client
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

	// Initialize MinIO client
	minioClient, err := minio.New(cfg.MinIO.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.MinIO.AccessKey, cfg.MinIO.SecretKey, ""),
		Secure: cfg.MinIO.UseSSL,
	})
	if err != nil {
		log.Fatalf("Failed to create MinIO client: %v", err)
	}

	// Ensure bucket exists
	ctx := context.Background()
	if err := minioClient.MakeBucket(ctx, cfg.MinIO.Bucket, minio.MakeBucketOptions{}); err != nil {
		// Check if bucket already exists
		exists, errBucketExists := minioClient.BucketExists(ctx, cfg.MinIO.Bucket)
		if errBucketExists != nil || !exists {
			log.Fatalf("Failed to create bucket: %v", err)
		}
	}

	service := &FileService{
		config:   cfg,
		db:       db,
		fileRepo: database.NewFileRepository(db),
		minio:    minioClient,
	}

	router := mux.NewRouter()
	router.Use(middleware.LoggingMiddleware)
	router.Use(middleware.RecoveryMiddleware)
	router.Use(middleware.CORSMiddleware([]string{"*"}))

	// Protected routes
	api := router.PathPrefix("/api/v1").Subrouter()
	api.Use(middleware.AuthMiddleware(&cfg.JWT))

	api.HandleFunc("/files/upload", service.UploadFile).Methods("POST")
	api.HandleFunc("/files/upload/{upload_id}", service.UploadChunk).Methods("PUT")
	api.HandleFunc("/files/{id}", service.DownloadFile).Methods("GET")
	api.HandleFunc("/files/{id}/info", service.GetFileInfo).Methods("GET")

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	go func() {
		log.Printf("File Service starting on port %d", cfg.Server.Port)
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
	log.Println("File Service stopped")
}

type UploadInitRequest struct {
	Filename     []byte `json:"filename"`      // Encrypted filename
	Size         int64  `json:"size"`
	ContentType  []byte `json:"content_type"`  // Encrypted content type
	EncryptedKey []byte `json:"encrypted_key"` // File key encrypted with session key
}

type UploadInitResponse struct {
	UploadID string `json:"upload_id"`
	ChunkSize int   `json:"chunk_size"`
}

func (s *FileService) UploadFile(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		sendError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	// Parse multipart form
	if err := r.ParseMultipartForm(MaxFileSize); err != nil {
		sendError(w, http.StatusBadRequest, "failed to parse form")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		sendError(w, http.StatusBadRequest, "no file provided")
		return
	}
	defer file.Close()

	if header.Size > MaxFileSize {
		sendError(w, http.StatusBadRequest, "file too large (max 100MB)")
		return
	}

	// Get metadata from form
	encryptedFilename := []byte(r.FormValue("filename"))
	encryptedContentType := []byte(r.FormValue("content_type"))
	encryptedKey := []byte(r.FormValue("encrypted_key"))

	// Generate storage key
	storageKey := uuid.New().String()

	// Upload to MinIO
	ctx := context.Background()
	_, err = s.minio.PutObject(ctx, s.config.MinIO.Bucket, storageKey, file, header.Size, minio.PutObjectOptions{
		ContentType: "application/octet-stream",
	})
	if err != nil {
		sendError(w, http.StatusInternalServerError, "failed to upload file")
		return
	}

	// Save metadata to database
	fileRecord := &models.File{
		ID:           uuid.New().String(),
		UploaderID:   userID,
		Filename:     encryptedFilename,
		Size:         header.Size,
		ContentType:  encryptedContentType,
		StorageKey:   storageKey,
		EncryptedKey: encryptedKey,
	}

	if err := s.fileRepo.Create(ctx, fileRecord); err != nil {
		// Clean up MinIO object
		s.minio.RemoveObject(ctx, s.config.MinIO.Bucket, storageKey, minio.RemoveObjectOptions{})
		sendError(w, http.StatusInternalServerError, "failed to save file metadata")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{
		Status: "success",
		Data: map[string]interface{}{
			"id":         fileRecord.ID,
			"size":       fileRecord.Size,
			"created_at": fileRecord.CreatedAt,
		},
	})
}

func (s *FileService) UploadChunk(w http.ResponseWriter, r *http.Request) {
	// For chunked upload (tus protocol or similar)
	// This is a simplified implementation
	sendError(w, http.StatusNotImplemented, "chunked upload not yet implemented")
}

func (s *FileService) DownloadFile(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		sendError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	vars := mux.Vars(r)
	fileID := vars["id"]

	// Get file metadata
	file, err := s.fileRepo.GetByID(r.Context(), fileID)
	if err != nil {
		sendError(w, http.StatusNotFound, "file not found")
		return
	}

	// TODO: Check if user has access to this file (via conversation membership)

	// Get object from MinIO
	ctx := context.Background()
	obj, err := s.minio.GetObject(ctx, s.config.MinIO.Bucket, file.StorageKey, minio.GetObjectOptions{})
	if err != nil {
		sendError(w, http.StatusInternalServerError, "failed to get file")
		return
	}
	defer obj.Close()

	// Set headers for encrypted file download
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fileID))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", file.Size))
	w.Header().Set("X-Encrypted-Key", fmt.Sprintf("%x", file.EncryptedKey))

	// Stream file
	io.Copy(w, obj)
}

func (s *FileService) GetFileInfo(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		sendError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	vars := mux.Vars(r)
	fileID := vars["id"]

	file, err := s.fileRepo.GetByID(r.Context(), fileID)
	if err != nil {
		sendError(w, http.StatusNotFound, "file not found")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{
		Status: "success",
		Data: map[string]interface{}{
			"id":            file.ID,
			"filename":      file.Filename,
			"size":          file.Size,
			"content_type":  file.ContentType,
			"encrypted_key": file.EncryptedKey,
			"created_at":    file.CreatedAt,
		},
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
