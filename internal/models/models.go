package models

import (
	"time"
)

// User represents a user in the system
type User struct {
	ID           string    `json:"id" db:"id"`
	Username     string    `json:"username" db:"username"`
	Email        string    `json:"email" db:"email"`
	PasswordHash string    `json:"-" db:"password_hash"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
	IsActive     bool      `json:"is_active" db:"is_active"`
}

// IdentityKey represents a user's long-term identity key
type IdentityKey struct {
	UserID    string    `json:"user_id" db:"user_id"`
	PublicKey []byte    `json:"public_key" db:"public_key"`
	Signature []byte    `json:"signature" db:"signature"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// SignedPreKey represents a user's signed prekey
type SignedPreKey struct {
	UserID    string    `json:"user_id" db:"user_id"`
	KeyID     uint32    `json:"key_id" db:"key_id"`
	PublicKey []byte    `json:"public_key" db:"public_key"`
	Signature []byte    `json:"signature" db:"signature"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// OneTimePreKey represents a user's one-time prekey
type OneTimePreKey struct {
	ID        string    `json:"id" db:"id"`
	UserID    string    `json:"user_id" db:"user_id"`
	KeyID     uint32    `json:"key_id" db:"key_id"`
	PublicKey []byte    `json:"public_key" db:"public_key"`
	Used      bool      `json:"used" db:"used"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// PreKeyBundle contains all keys needed to initiate a session
type PreKeyBundle struct {
	IdentityKey   []byte `json:"identity_key"`
	SignedPreKey  []byte `json:"signed_pre_key"`
	Signature     []byte `json:"signature"`
	OneTimePreKey []byte `json:"one_time_pre_key,omitempty"`
}

// Conversation represents a chat (individual or group)
type Conversation struct {
	ID          string          `json:"id" db:"id"`
	Type        ConversationType `json:"type" db:"type"`
	Name        string          `json:"name,omitempty" db:"name"`
	CreatedAt   time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at" db:"updated_at"`
	CreatedBy   string          `json:"created_by" db:"created_by"`
}

type ConversationType string

const (
	ConversationTypeIndividual ConversationType = "individual"
	ConversationTypeGroup      ConversationType = "group"
)

// ConversationMember represents a user's membership in a conversation
type ConversationMember struct {
	ConversationID string    `json:"conversation_id" db:"conversation_id"`
	UserID        string    `json:"user_id" db:"user_id"`
	Role          MemberRole `json:"role" db:"role"`
	JoinedAt      time.Time `json:"joined_at" db:"joined_at"`
}

type MemberRole string

const (
	RoleMember MemberRole = "member"
	RoleAdmin  MemberRole = "admin"
	RoleOwner  MemberRole = "owner"
)

// Message represents an encrypted message
type Message struct {
	ID             string    `json:"id" db:"id"`
	ConversationID string    `json:"conversation_id" db:"conversation_id"`
	SenderID       string    `json:"sender_id" db:"sender_id"`
	Content        []byte    `json:"content" db:"content"` // Encrypted content
	MessageType    MessageType `json:"message_type" db:"message_type"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
}

type MessageType string

const (
	MessageTypeText  MessageType = "text"
	MessageTypeFile  MessageType = "file"
	MessageTypeInfo  MessageType = "info"
)

// File represents an encrypted file
type File struct {
	ID          string    `json:"id" db:"id"`
	UploaderID  string    `json:"uploader_id" db:"uploader_id"`
	Filename    string    `json:"filename" db:"filename"` // Encrypted
	Size        int64     `json:"size" db:"size"`
	ContentType string    `json:"content_type" db:"content_type"` // Encrypted
	StorageKey  string    `json:"-" db:"storage_key"`
	EncryptedKey []byte   `json:"encrypted_key" db:"encrypted_key"` // File key encrypted with session key
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

// WebSocketMessage represents a message sent over WebSocket
type WebSocketMessage struct {
	Type      MessageType `json:"type"`
	Payload   []byte      `json:"payload"`
	Timestamp int64       `json:"timestamp"`
}

// WSMessageType represents WebSocket message types
type WSMessageType uint8

const (
	WSMessageSend     WSMessageType = 1
	WSMessageReceive  WSMessageType = 2
	WSTypingIndicator WSMessageType = 3
	WSReadReceipt     WSMessageType = 4
	WSPresenceUpdate  WSMessageType = 5
	WSError           WSMessageType = 255
)

// WSMessage represents a WebSocket protocol message
type WSMessage struct {
	Type      WSMessageType `json:"type"`
	Payload   interface{}   `json:"payload"`
	Timestamp int64         `json:"timestamp"`
}

// MessagePayload represents the payload for message send/receive
type MessagePayload struct {
	MessageID      string `json:"message_id"`
	ConversationID string `json:"conversation_id"`
	SenderID       string `json:"sender_id"`
	Content        []byte `json:"content"`
	MessageType    string `json:"message_type"`
	Timestamp      int64  `json:"timestamp"`
}

// TypingPayload represents typing indicator payload
type TypingPayload struct {
	ConversationID string `json:"conversation_id"`
	UserID         string `json:"user_id"`
	IsTyping       bool   `json:"is_typing"`
}

// ReadReceiptPayload represents read receipt payload
type ReadReceiptPayload struct {
	ConversationID string `json:"conversation_id"`
	MessageID      string `json:"message_id"`
	UserID         string `json:"user_id"`
	Timestamp      int64  `json:"timestamp"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// APIResponse represents a standard API response
type APIResponse struct {
	Status  string      `json:"status"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Message string      `json:"message,omitempty"`
}

// PaginationParams represents pagination parameters
type PaginationParams struct {
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

// PaginatedResponse represents a paginated response
type PaginatedResponse struct {
	Data       interface{} `json:"data"`
	Total      int64       `json:"total"`
	Limit      int         `json:"limit"`
	Offset     int         `json:"offset"`
	HasMore    bool        `json:"has_more"`
}
