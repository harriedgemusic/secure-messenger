package crypto

import (
	"bytes"
	"testing"
)

func TestPasswordHashAndVerify(t *testing.T) {
	password := "supersecurepassword123"

	// Test hashing with auto-generated salt
	hash1, err := PasswordHash(password, nil)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	if len(hash1) != Argon2SaltSize+KeySize {
		t.Errorf("Expected hash length %d, got %d", Argon2SaltSize+KeySize, len(hash1))
	}

	// Test verification with correct password
	valid, err := VerifyPassword(password, hash1)
	if err != nil {
		t.Fatalf("Failed to verify password: %v", err)
	}
	if !valid {
		t.Error("Expected password to be valid")
	}

	// Test verification with incorrect password
	valid, err = VerifyPassword("wrongpassword", hash1)
	if err != nil {
		t.Fatalf("Failed to verify password: %v", err)
	}
	if valid {
		t.Error("Expected password to be invalid")
	}

	// Test hashing with provided salt
	salt := make([]byte, Argon2SaltSize)
	for i := range salt {
		salt[i] = byte(i)
	}
	hash2, err := PasswordHash(password, salt)
	if err != nil {
		t.Fatalf("Failed to hash password with salt: %v", err)
	}
	if !bytes.Equal(hash2[:Argon2SaltSize], salt) {
		t.Error("Expected salt to match provided salt")
	}
}

func TestAESGCMEncryptDecrypt(t *testing.T) {
	key, err := GenerateRandomBytes(KeySize)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	plaintext := []byte("secret message")
	associatedData := []byte("metadata")

	// Test encryption
	ciphertext, nonce, err := AESGCMEncrypt(key, plaintext, associatedData)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	if len(nonce) != NonceSize {
		t.Errorf("Expected nonce length %d, got %d", NonceSize, len(nonce))
	}

	// Test decryption with correct key and AD
	decrypted, err := AESGCMDecrypt(key, ciphertext, nonce, associatedData)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Expected decrypted text %q, got %q", plaintext, decrypted)
	}

	// Test decryption with incorrect key
	wrongKey, _ := GenerateRandomBytes(KeySize)
	_, err = AESGCMDecrypt(wrongKey, ciphertext, nonce, associatedData)
	if err == nil {
		t.Error("Expected decryption to fail with wrong key")
	}

	// Test decryption with incorrect associated data
	wrongAD := []byte("wrong metadata")
	_, err = AESGCMDecrypt(key, ciphertext, nonce, wrongAD)
	if err == nil {
		t.Error("Expected decryption to fail with wrong associated data")
	}
}

func TestEd25519Signing(t *testing.T) {
	pub, priv, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	message := []byte("document to sign")

	// Test signing
	signature := Sign(priv, message)
	if len(signature) != SignatureSize {
		t.Errorf("Expected signature length %d, got %d", SignatureSize, len(signature))
	}

	// Test verification
	valid := VerifySignature(pub, message, signature)
	if !valid {
		t.Error("Expected signature to be valid")
	}

	// Test verification with wrong message
	valid = VerifySignature(pub, []byte("wrong document"), signature)
	if valid {
		t.Error("Expected signature to be invalid for wrong message")
	}
}

func TestX25519DH(t *testing.T) {
	pubA, privA, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair A: %v", err)
	}

	pubB, privB, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair B: %v", err)
	}

	// Compute shared secret from A's perspective
	secretA, err := DH(privA, pubB)
	if err != nil {
		t.Fatalf("Failed to compute shared secret A: %v", err)
	}

	// Compute shared secret from B's perspective
	secretB, err := DH(privB, pubA)
	if err != nil {
		t.Fatalf("Failed to compute shared secret B: %v", err)
	}

	// Verify secrets match
	if !bytes.Equal(secretA, secretB) {
		t.Error("Expected shared secrets to match")
	}
}
