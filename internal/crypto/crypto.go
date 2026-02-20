package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// Key sizes
	KeySize       = 32
	NonceSize     = 12
	SignatureSize = 64

	// Argon2 parameters
	Argon2Memory   = 64 * 1024 // 64 MB
	Argon2Time     = 3
	Argon2Threads  = 4
	Argon2SaltSize = 16
)

var (
	ErrInvalidKeySize   = errors.New("invalid key size")
	ErrInvalidNonceSize = errors.New("invalid nonce size")
	ErrDecryptFailed    = errors.New("decryption failed")
	ErrInvalidSignature = errors.New("invalid signature")
)

// PasswordHash generates an Argon2id hash of the password
func PasswordHash(password string, salt []byte) ([]byte, error) {
	if len(salt) == 0 {
		salt = make([]byte, Argon2SaltSize)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, err
		}
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		Argon2Time,
		Argon2Memory,
		Argon2Threads,
		KeySize,
	)

	// Return salt + hash
	result := make([]byte, Argon2SaltSize+KeySize)
	copy(result[:Argon2SaltSize], salt)
	copy(result[Argon2SaltSize:], hash)
	return result, nil
}

// VerifyPassword verifies a password against a stored hash
func VerifyPassword(password string, storedHash []byte) (bool, error) {
	if len(storedHash) != Argon2SaltSize+KeySize {
		return false, ErrInvalidKeySize
	}

	salt := storedHash[:Argon2SaltSize]
	expectedHash := storedHash[Argon2SaltSize:]

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		Argon2Time,
		Argon2Memory,
		Argon2Threads,
		KeySize,
	)

	return subtleCompare(hash, expectedHash), nil
}

// GenerateKeyPair generates an X25519 key pair for DH key exchange
func GenerateKeyPair() (publicKey, privateKey []byte, error error) {
	publicKey, privateKey, err := curve25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return publicKey[:], privateKey[:], nil
}

// GenerateSigningKeyPair generates an Ed25519 key pair for signing
func GenerateSigningKeyPair() (publicKey, privateKey []byte, error error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return publicKey, privateKey, nil
}

// Sign signs a message with Ed25519 private key
func Sign(privateKey, message []byte) []byte {
	return ed25519.Sign(ed25519.PrivateKey(privateKey), message)
}

// VerifySignature verifies an Ed25519 signature
func VerifySignature(publicKey, message, signature []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(publicKey), message, signature)
}

// DH computes a shared secret using X25519
func DH(privateKey, publicKey []byte) ([]byte, error) {
	if len(privateKey) != 32 || len(publicKey) != 32 {
		return nil, ErrInvalidKeySize
	}

	var sharedSecret [32]byte
	var priv, pub [32]byte
	copy(priv[:], privateKey)
	copy(pub[:], publicKey)

	curve25519.ScalarMult(&sharedSecret, &priv, &pub)
	return sharedSecret[:], nil
}

// AESGCMEncrypt encrypts data using AES-256-GCM
func AESGCMEncrypt(key, plaintext, associatedData []byte) (ciphertext, nonce []byte, error error) {
	if len(key) != KeySize {
		return nil, nil, ErrInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, associatedData)
	return ciphertext, nonce, nil
}

// AESGCMDecrypt decrypts data using AES-256-GCM
func AESGCMDecrypt(key, ciphertext, nonce, associatedData []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(nonce) != gcm.NonceSize() {
		return nil, ErrInvalidNonceSize
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, associatedData)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	return plaintext, nil
}

// GenerateRandomBytes generates cryptographically secure random bytes
func GenerateRandomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}

// DeriveKey derives a key from a secret using HKDF-SHA256
func DeriveKey(secret, salt, info []byte, keyLen int) ([]byte, error) {
	hkdf := hkdf.New(sha256.New, secret, salt, info)
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateNonce generates a random nonce for AES-GCM
func GenerateNonce() ([]byte, error) {
	return GenerateRandomBytes(NonceSize)
}

// subtleCompare performs a constant-time comparison
func subtleCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}

	return result == 0
}
