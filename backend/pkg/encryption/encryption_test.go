package encryption

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	// Use a valid 32-byte key for AES-256
	key := []byte("12345678901234567890123456789012")
	plaintext := "Hello, World!"

	// Test Encryption
	encryptedData, err := Encrypt([]byte(plaintext), key)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	if len(encryptedData.Ciphertext) == 0 {
		t.Fatal("Ciphertext is empty")
	}

	if len(encryptedData.Nonce) == 0 {
		t.Fatal("Nonce is empty")
	}

	if string(encryptedData.Ciphertext) == plaintext {
		t.Fatal("Ciphertext should not match plaintext")
	}

	// Test Decryption
	decrypted, err := Decrypt(encryptedData, key)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if string(decrypted) != plaintext {
		t.Errorf("Expected %s, got %s", plaintext, decrypted)
	}
}

func TestEncryptUniqueness(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	plaintext := "Hello, World!"

	c1, err := Encrypt([]byte(plaintext), key)
	if err != nil {
		t.Fatal(err)
	}

	c2, err := Encrypt([]byte(plaintext), key)
	if err != nil {
		t.Fatal(err)
	}

	// Compare nonces - they should be different
	if bytes.Equal(c1.Nonce, c2.Nonce) {
		t.Error("Encryption should produce different nonces for same input")
	}

	// Ciphertexts should also be different due to different nonces
	if bytes.Equal(c1.Ciphertext, c2.Ciphertext) {
		t.Error("Encryption should produce different ciphertexts for same input (nonce usage)")
	}
}

func TestInvalidKey(t *testing.T) {
	key := []byte("shortkey")
	_, err := Encrypt([]byte("test"), key)
	if err == nil {
		t.Error("Expected error with invalid key size")
	}
}

func TestDecryptInvalidData(t *testing.T) {
	key := []byte("12345678901234567890123456789012")

	// Test with corrupted ciphertext (valid nonce size but invalid ciphertext)
	invalidData := &EncryptedData{
		Nonce:      make([]byte, 12), // Valid nonce size for GCM
		Ciphertext: []byte("corrupted data that won't decrypt"),
	}
	_, err := Decrypt(invalidData, key)
	if err == nil {
		t.Error("Expected error decrypting corrupted ciphertext")
	}

	// Test with empty ciphertext
	emptyData := &EncryptedData{
		Nonce:      make([]byte, 12), // Valid nonce size for GCM
		Ciphertext: []byte{},
	}
	_, err = Decrypt(emptyData, key)
	if err == nil {
		t.Error("Expected error decrypting empty ciphertext")
	}
}
