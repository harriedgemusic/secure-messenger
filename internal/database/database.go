package database

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/secure-messenger/internal/config"
	"github.com/secure-messenger/internal/models"
)

type Database struct {
	pool *pgxpool.Pool
}

func New(cfg *config.DatabaseConfig) (*Database, error) {
	poolConfig, err := pgxpool.ParseConfig(cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("failed to parse database config: %w", err)
	}

	poolConfig.MaxConns = int32(cfg.MaxOpenConns)
	poolConfig.MinConns = int32(cfg.MaxIdleConns)
	poolConfig.MaxConnLifetime = cfg.ConnMaxLifetime
	poolConfig.MaxConnIdleTime = 5 * time.Minute

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &Database{pool: pool}, nil
}

func (db *Database) Close() {
	db.pool.Close()
}

func (db *Database) Pool() *pgxpool.Pool {
	return db.pool
}

// Migrate runs database migrations
func (db *Database) Migrate(ctx context.Context) error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			username VARCHAR(255) UNIQUE NOT NULL,
			email VARCHAR(255) UNIQUE NOT NULL,
			password_hash BYTEA NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			is_active BOOLEAN DEFAULT true
		)`,
		`CREATE TABLE IF NOT EXISTS identity_keys (
			user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
			public_key BYTEA NOT NULL,
			signature BYTEA NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS signed_prekeys (
			user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
			key_id BIGINT NOT NULL,
			public_key BYTEA NOT NULL,
			signature BYTEA NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS one_time_prekeys (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			key_id BIGINT NOT NULL,
			public_key BYTEA NOT NULL,
			used BOOLEAN DEFAULT false,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_one_time_prekeys_user_used ON one_time_prekeys(user_id, used)`,
		`CREATE TABLE IF NOT EXISTS conversations (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			type VARCHAR(20) NOT NULL,
			name VARCHAR(255),
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			created_by UUID REFERENCES users(id)
		)`,
		`CREATE TABLE IF NOT EXISTS conversation_members (
			conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
			user_id UUID REFERENCES users(id) ON DELETE CASCADE,
			role VARCHAR(20) NOT NULL DEFAULT 'member',
			joined_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			PRIMARY KEY (conversation_id, user_id)
		)`,
		`CREATE TABLE IF NOT EXISTS messages (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
			sender_id UUID NOT NULL REFERENCES users(id),
			content BYTEA NOT NULL,
			message_type VARCHAR(20) NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_messages_conversation_time ON messages(conversation_id, created_at DESC)`,
		`CREATE TABLE IF NOT EXISTS files (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			uploader_id UUID NOT NULL REFERENCES users(id),
			filename BYTEA NOT NULL,
			size BIGINT NOT NULL,
			content_type BYTEA NOT NULL,
			storage_key VARCHAR(255) NOT NULL,
			encrypted_key BYTEA NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_files_uploader ON files(uploader_id)`,
	}

	for i, migration := range migrations {
		if _, err := db.pool.Exec(ctx, migration); err != nil {
			return fmt.Errorf("migration %d failed: %w", i+1, err)
		}
	}

	return nil
}

// UserRepository handles user database operations
type UserRepository struct {
	db *Database
}

func NewUserRepository(db *Database) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
	query := `
		INSERT INTO users (username, email, password_hash, is_active)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at, updated_at
	`
	return r.db.pool.QueryRow(ctx, query,
		user.Username,
		user.Email,
		user.PasswordHash,
		user.IsActive,
	).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)
}

func (r *UserRepository) GetByID(ctx context.Context, id string) (*models.User, error) {
	user := &models.User{}
	query := `
		SELECT id, username, email, password_hash, created_at, updated_at, is_active
		FROM users WHERE id = $1
	`
	err := r.db.pool.QueryRow(ctx, query, id).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash,
		&user.CreatedAt, &user.UpdatedAt, &user.IsActive,
	)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *UserRepository) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	user := &models.User{}
	query := `
		SELECT id, username, email, password_hash, created_at, updated_at, is_active
		FROM users WHERE username = $1
	`
	err := r.db.pool.QueryRow(ctx, query, username).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash,
		&user.CreatedAt, &user.UpdatedAt, &user.IsActive,
	)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	user := &models.User{}
	query := `
		SELECT id, username, email, password_hash, created_at, updated_at, is_active
		FROM users WHERE email = $1
	`
	err := r.db.pool.QueryRow(ctx, query, email).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash,
		&user.CreatedAt, &user.UpdatedAt, &user.IsActive,
	)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// KeyRepository handles key database operations
type KeyRepository struct {
	db *Database
}

func NewKeyRepository(db *Database) *KeyRepository {
	return &KeyRepository{db: db}
}

func (r *KeyRepository) StoreIdentityKey(ctx context.Context, ik *models.IdentityKey) error {
	query := `
		INSERT INTO identity_keys (user_id, public_key, signature)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id) DO UPDATE SET public_key = $2, signature = $3, created_at = NOW()
	`
	_, err := r.db.pool.Exec(ctx, query, ik.UserID, ik.PublicKey, ik.Signature)
	return err
}

func (r *KeyRepository) GetIdentityKey(ctx context.Context, userID string) (*models.IdentityKey, error) {
	ik := &models.IdentityKey{}
	query := `SELECT user_id, public_key, signature, created_at FROM identity_keys WHERE user_id = $1`
	err := r.db.pool.QueryRow(ctx, query, userID).Scan(
		&ik.UserID, &ik.PublicKey, &ik.Signature, &ik.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return ik, nil
}

func (r *KeyRepository) StoreSignedPreKey(ctx context.Context, spk *models.SignedPreKey) error {
	query := `
		INSERT INTO signed_prekeys (user_id, key_id, public_key, signature)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id) DO UPDATE SET key_id = $2, public_key = $3, signature = $4, created_at = NOW()
	`
	_, err := r.db.pool.Exec(ctx, query, spk.UserID, spk.KeyID, spk.PublicKey, spk.Signature)
	return err
}

func (r *KeyRepository) GetSignedPreKey(ctx context.Context, userID string) (*models.SignedPreKey, error) {
	spk := &models.SignedPreKey{}
	query := `SELECT user_id, key_id, public_key, signature, created_at FROM signed_prekeys WHERE user_id = $1`
	err := r.db.pool.QueryRow(ctx, query, userID).Scan(
		&spk.UserID, &spk.KeyID, &spk.PublicKey, &spk.Signature, &spk.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return spk, nil
}

func (r *KeyRepository) StoreOneTimePreKeys(ctx context.Context, otpks []*models.OneTimePreKey) error {
	tx, err := r.db.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	query := `
		INSERT INTO one_time_prekeys (user_id, key_id, public_key)
		VALUES ($1, $2, $3)
	`
	for _, otpk := range otpks {
		if _, err := tx.Exec(ctx, query, otpk.UserID, otpk.KeyID, otpk.PublicKey); err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

func (r *KeyRepository) GetOneTimePreKey(ctx context.Context, userID string) (*models.OneTimePreKey, error) {
	tx, err := r.db.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	otpk := &models.OneTimePreKey{}
	query := `
		UPDATE one_time_prekeys SET used = true
		WHERE id = (SELECT id FROM one_time_prekeys WHERE user_id = $1 AND used = false LIMIT 1 FOR UPDATE SKIP LOCKED)
		RETURNING id, user_id, key_id, public_key, used, created_at
	`
	err = tx.QueryRow(ctx, query, userID).Scan(
		&otpk.ID, &otpk.UserID, &otpk.KeyID, &otpk.PublicKey, &otpk.Used, &otpk.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return otpk, nil
}

func (r *KeyRepository) GetPreKeyBundle(ctx context.Context, userID string) (*models.PreKeyBundle, error) {
	bundle := &models.PreKeyBundle{}

	ik, err := r.GetIdentityKey(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get identity key: %w", err)
	}
	bundle.IdentityKey = ik.PublicKey

	spk, err := r.GetSignedPreKey(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get signed prekey: %w", err)
	}
	bundle.SignedPreKey = spk.PublicKey
	bundle.Signature = spk.Signature

	otpk, err := r.GetOneTimePreKey(ctx, userID)
	if err == nil {
		bundle.OneTimePreKey = otpk.PublicKey
	}

	return bundle, nil
}

// MessageRepository handles message database operations
type MessageRepository struct {
	db *Database
}

func NewMessageRepository(db *Database) *MessageRepository {
	return &MessageRepository{db: db}
}

func (r *MessageRepository) Create(ctx context.Context, msg *models.Message) error {
	query := `
		INSERT INTO messages (conversation_id, sender_id, content, message_type)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at
	`
	return r.db.pool.QueryRow(ctx, query,
		msg.ConversationID,
		msg.SenderID,
		msg.Content,
		msg.MessageType,
	).Scan(&msg.ID, &msg.CreatedAt)
}

func (r *MessageRepository) GetByConversation(ctx context.Context, conversationID string, limit, offset int) ([]models.Message, error) {
	query := `
		SELECT id, conversation_id, sender_id, content, message_type, created_at
		FROM messages
		WHERE conversation_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`
	rows, err := r.db.pool.Query(ctx, query, conversationID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []models.Message
	for rows.Next() {
		var msg models.Message
		if err := rows.Scan(
			&msg.ID, &msg.ConversationID, &msg.SenderID,
			&msg.Content, &msg.MessageType, &msg.CreatedAt,
		); err != nil {
			return nil, err
		}
		messages = append(messages, msg)
	}

	return messages, rows.Err()
}

// ConversationRepository handles conversation database operations
type ConversationRepository struct {
	db *Database
}

func NewConversationRepository(db *Database) *ConversationRepository {
	return &ConversationRepository{db: db}
}

func (r *ConversationRepository) Create(ctx context.Context, conv *models.Conversation) error {
	query := `
		INSERT INTO conversations (type, name, created_by)
		VALUES ($1, $2, $3)
		RETURNING id, created_at, updated_at
	`
	return r.db.pool.QueryRow(ctx, query,
		conv.Type,
		conv.Name,
		conv.CreatedBy,
	).Scan(&conv.ID, &conv.CreatedAt, &conv.UpdatedAt)
}

func (r *ConversationRepository) AddMember(ctx context.Context, member *models.ConversationMember) error {
	query := `
		INSERT INTO conversation_members (conversation_id, user_id, role)
		VALUES ($1, $2, $3)
		ON CONFLICT DO NOTHING
	`
	_, err := r.db.pool.Exec(ctx, query, member.ConversationID, member.UserID, member.Role)
	return err
}

func (r *ConversationRepository) GetByID(ctx context.Context, id string) (*models.Conversation, error) {
	conv := &models.Conversation{}
	query := `
		SELECT id, type, name, created_at, updated_at, created_by
		FROM conversations WHERE id = $1
	`
	err := r.db.pool.QueryRow(ctx, query, id).Scan(
		&conv.ID, &conv.Type, &conv.Name, &conv.CreatedAt, &conv.UpdatedAt, &conv.CreatedBy,
	)
	if err != nil {
		return nil, err
	}
	return conv, nil
}

func (r *ConversationRepository) GetMembers(ctx context.Context, conversationID string) ([]models.ConversationMember, error) {
	query := `
		SELECT conversation_id, user_id, role, joined_at
		FROM conversation_members WHERE conversation_id = $1
	`
	rows, err := r.db.pool.Query(ctx, query, conversationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []models.ConversationMember
	for rows.Next() {
		var m models.ConversationMember
		if err := rows.Scan(&m.ConversationID, &m.UserID, &m.Role, &m.JoinedAt); err != nil {
			return nil, err
		}
		members = append(members, m)
	}

	return members, rows.Err()
}

// FileRepository handles file database operations
type FileRepository struct {
	db *Database
}

func NewFileRepository(db *Database) *FileRepository {
	return &FileRepository{db: db}
}

func (r *FileRepository) Create(ctx context.Context, file *models.File) error {
	query := `
		INSERT INTO files (uploader_id, filename, size, content_type, storage_key, encrypted_key)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at
	`
	return r.db.pool.QueryRow(ctx, query,
		file.UploaderID,
		file.Filename,
		file.Size,
		file.ContentType,
		file.StorageKey,
		file.EncryptedKey,
	).Scan(&file.ID, &file.CreatedAt)
}

func (r *FileRepository) GetByID(ctx context.Context, id string) (*models.File, error) {
	file := &models.File{}
	query := `
		SELECT id, uploader_id, filename, size, content_type, storage_key, encrypted_key, created_at
		FROM files WHERE id = $1
	`
	err := r.db.pool.QueryRow(ctx, query, id).Scan(
		&file.ID, &file.UploaderID, &file.Filename, &file.Size,
		&file.ContentType, &file.StorageKey, &file.EncryptedKey, &file.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return file, nil
}
