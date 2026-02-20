package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/secure-messenger/internal/config"
	"github.com/secure-messenger/internal/database"
	"github.com/secure-messenger/internal/middleware"
	"github.com/secure-messenger/internal/models"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Configure properly in production
	},
}

type MessageService struct {
	config     *config.Config
	db         *database.Database
	msgRepo    *database.MessageRepository
	convRepo   *database.ConversationRepository
	userRepo   *database.UserRepository
	connections *ConnectionManager
}

type ConnectionManager struct {
	mu       sync.RWMutex
	clients  map[string][]*websocket.Conn // userID -> connections
	userIDs  map[*websocket.Conn]string   // connection -> userID
}

func NewConnectionManager() *ConnectionManager {
	return &ConnectionManager{
		clients: make(map[string][]*websocket.Conn),
		userIDs: make(map[*websocket.Conn]string),
	}
}

func (cm *ConnectionManager) AddConnection(userID string, conn *websocket.Conn) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.clients[userID] = append(cm.clients[userID], conn)
	cm.userIDs[conn] = userID
}

func (cm *ConnectionManager) RemoveConnection(conn *websocket.Conn) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	userID, ok := cm.userIDs[conn]
	if !ok {
		return
	}

	delete(cm.userIDs, conn)

	connections := cm.clients[userID]
	for i, c := range connections {
		if c == conn {
			cm.clients[userID] = append(connections[:i], connections[i+1:]...)
			break
		}
	}

	if len(cm.clients[userID]) == 0 {
		delete(cm.clients, userID)
	}
}

func (cm *ConnectionManager) GetConnections(userID string) []*websocket.Conn {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	return cm.clients[userID]
}

func (cm *ConnectionManager) GetUserID(conn *websocket.Conn) string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	return cm.userIDs[conn]
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

	service := &MessageService{
		config:      cfg,
		db:          db,
		msgRepo:     database.NewMessageRepository(db),
		convRepo:    database.NewConversationRepository(db),
		userRepo:    database.NewUserRepository(db),
		connections: NewConnectionManager(),
	}

	router := mux.NewRouter()
	router.Use(middleware.LoggingMiddleware)
	router.Use(middleware.RecoveryMiddleware)
	router.Use(middleware.CORSMiddleware([]string{"*"}))

	// WebSocket endpoint
	router.HandleFunc("/ws", service.HandleWebSocket)

	// REST API endpoints (protected)
	api := router.PathPrefix("/api/v1").Subrouter()
	api.Use(middleware.AuthMiddleware(&cfg.JWT))

	// Conversations
	api.HandleFunc("/conversations", service.CreateConversation).Methods("POST")
	api.HandleFunc("/conversations", service.GetConversations).Methods("GET")
	api.HandleFunc("/conversations/{id}", service.GetConversation).Methods("GET")
	api.HandleFunc("/conversations/{id}/members", service.AddMember).Methods("POST")
	api.HandleFunc("/conversations/{id}/members", service.GetMembers).Methods("GET")

	// Messages
	api.HandleFunc("/conversations/{id}/messages", service.GetMessages).Methods("GET")

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	go func() {
		log.Printf("Message Service starting on port %d", cfg.Server.Port)
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
	log.Println("Message Service stopped")
}

func (s *MessageService) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Get token from query parameter
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}

	// Validate token and get user ID
	userID, err := s.validateToken(token)
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	s.connections.AddConnection(userID, conn)
	log.Printf("WebSocket connected: user=%s", userID)

	defer func() {
		s.connections.RemoveConnection(conn)
		conn.Close()
		log.Printf("WebSocket disconnected: user=%s", userID)
	}()

	// Send connection acknowledgment
	s.sendWSMessage(conn, models.WSMessage{
		Type:      0, // Connection established
		Payload:   map[string]string{"status": "connected"},
		Timestamp: time.Now().Unix(),
	})

	// Read messages
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket read error: %v", err)
			}
			break
		}

		var wsMsg models.WSMessage
		if err := json.Unmarshal(message, &wsMsg); err != nil {
			s.sendWSError(conn, "invalid message format")
			continue
		}

		s.handleWSMessage(conn, userID, wsMsg)
	}
}

func (s *MessageService) handleWSMessage(conn *websocket.Conn, userID string, msg models.WSMessage) {
	switch msg.Type {
	case models.WSMessageSend:
		s.handleSendMessage(conn, userID, msg.Payload)
	case models.WSTypingIndicator:
		s.handleTypingIndicator(userID, msg.Payload)
	case models.WSReadReceipt:
		s.handleReadReceipt(userID, msg.Payload)
	default:
		s.sendWSError(conn, "unknown message type")
	}
}

type SendMessagePayload struct {
	ConversationID string          `json:"conversation_id"`
	Content        []byte          `json:"content"`
	MessageType    models.MessageType `json:"message_type"`
}

func (s *MessageService) handleSendMessage(conn *websocket.Conn, userID string, payload interface{}) {
	data, err := json.Marshal(payload)
	if err != nil {
		s.sendWSError(conn, "invalid payload")
		return
	}

	var p SendMessagePayload
	if err := json.Unmarshal(data, &p); err != nil {
		s.sendWSError(conn, "invalid message payload")
		return
	}

	// Create message
	msg := &models.Message{
		ID:             uuid.New().String(),
		ConversationID: p.ConversationID,
		SenderID:       userID,
		Content:        p.Content,
		MessageType:    p.MessageType,
	}

	if err := s.msgRepo.Create(context.Background(), msg); err != nil {
		s.sendWSError(conn, "failed to save message")
		return
	}

	// Get conversation members
	members, err := s.convRepo.GetMembers(context.Background(), p.ConversationID)
	if err != nil {
		s.sendWSError(conn, "failed to get conversation members")
		return
	}

	// Broadcast to all members
	wsMsg := models.WSMessage{
		Type: models.WSMessageReceive,
		Payload: models.MessagePayload{
			MessageID:      msg.ID,
			ConversationID: msg.ConversationID,
			SenderID:       msg.SenderID,
			Content:        msg.Content,
			MessageType:    string(msg.MessageType),
			Timestamp:      msg.CreatedAt.Unix(),
		},
		Timestamp: time.Now().Unix(),
	}

	for _, member := range members {
		connections := s.connections.GetConnections(member.UserID)
		for _, c := range connections {
			s.sendWSMessage(c, wsMsg)
		}
	}
}

func (s *MessageService) handleTypingIndicator(userID string, payload interface{}) {
	data, _ := json.Marshal(payload)
	var p models.TypingPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return
	}

	p.UserID = userID

	members, err := s.convRepo.GetMembers(context.Background(), p.ConversationID)
	if err != nil {
		return
	}

	wsMsg := models.WSMessage{
		Type:      models.WSTypingIndicator,
		Payload:   p,
		Timestamp: time.Now().Unix(),
	}

	for _, member := range members {
		if member.UserID != userID {
			connections := s.connections.GetConnections(member.UserID)
			for _, c := range connections {
				s.sendWSMessage(c, wsMsg)
			}
		}
	}
}

func (s *MessageService) handleReadReceipt(userID string, payload interface{}) {
	data, _ := json.Marshal(payload)
	var p models.ReadReceiptPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return
	}

	p.UserID = userID

	members, err := s.convRepo.GetMembers(context.Background(), p.ConversationID)
	if err != nil {
		return
	}

	wsMsg := models.WSMessage{
		Type:      models.WSReadReceipt,
		Payload:   p,
		Timestamp: time.Now().Unix(),
	}

	for _, member := range members {
		connections := s.connections.GetConnections(member.UserID)
		for _, c := range connections {
			s.sendWSMessage(c, wsMsg)
		}
	}
}

func (s *MessageService) sendWSMessage(conn *websocket.Conn, msg models.WSMessage) error {
	return conn.WriteJSON(msg)
}

func (s *MessageService) sendWSError(conn *websocket.Conn, message string) {
	s.sendWSMessage(conn, models.WSMessage{
		Type: models.WSError,
		Payload: map[string]string{
			"error": message,
		},
		Timestamp: time.Now().Unix(),
	})
}

func (s *MessageService) validateToken(token string) (string, error) {
	// Simple JWT validation - use proper validation in production
	// This is a placeholder
	return "user-id-from-token", nil
}

// REST API handlers

type CreateConversationRequest struct {
	Type    models.ConversationType `json:"type"`
	Name    string                  `json:"name,omitempty"`
	Members []string                `json:"members"`
}

func (s *MessageService) CreateConversation(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		sendError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req CreateConversationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	conv := &models.Conversation{
		Type:      req.Type,
		Name:      req.Name,
		CreatedBy: userID,
	}

	if err := s.convRepo.Create(r.Context(), conv); err != nil {
		sendError(w, http.StatusInternalServerError, "failed to create conversation")
		return
	}

	// Add creator as owner
	if err := s.convRepo.AddMember(r.Context(), &models.ConversationMember{
		ConversationID: conv.ID,
		UserID:        userID,
		Role:          models.RoleOwner,
	}); err != nil {
		sendError(w, http.StatusInternalServerError, "failed to add creator to conversation")
		return
	}

	// Add other members
	for _, memberID := range req.Members {
		if memberID != userID {
			s.convRepo.AddMember(r.Context(), &models.ConversationMember{
				ConversationID: conv.ID,
				UserID:        memberID,
				Role:          models.RoleMember,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{
		Status: "success",
		Data:   conv,
	})
}

func (s *MessageService) GetConversations(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement getting user's conversations
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{
		Status: "success",
		Data:   []interface{}{},
	})
}

func (s *MessageService) GetConversation(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	convID := vars["id"]

	conv, err := s.convRepo.GetByID(r.Context(), convID)
	if err != nil {
		sendError(w, http.StatusNotFound, "conversation not found")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{
		Status: "success",
		Data:   conv,
	})
}

func (s *MessageService) AddMember(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	convID := vars["id"]

	var req struct {
		UserID string             `json:"user_id"`
		Role   models.MemberRole  `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Role == "" {
		req.Role = models.RoleMember
	}

	if err := s.convRepo.AddMember(r.Context(), &models.ConversationMember{
		ConversationID: convID,
		UserID:        req.UserID,
		Role:          req.Role,
	}); err != nil {
		sendError(w, http.StatusInternalServerError, "failed to add member")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{
		Status:  "success",
		Message: "member added",
	})
}

func (s *MessageService) GetMembers(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	convID := vars["id"]

	members, err := s.convRepo.GetMembers(r.Context(), convID)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "failed to get members")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{
		Status: "success",
		Data:   members,
	})
}

func (s *MessageService) GetMessages(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	convID := vars["id"]

	limit := 50
	offset := 0

	if l := r.URL.Query().Get("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		fmt.Sscanf(o, "%d", &offset)
	}

	messages, err := s.msgRepo.GetByConversation(r.Context(), convID, limit, offset)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "failed to get messages")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{
		Status: "success",
		Data:   messages,
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
