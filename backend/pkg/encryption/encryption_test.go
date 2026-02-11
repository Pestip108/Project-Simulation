package encryption

import (
	"encoding/base64"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key := []byte("thisisaveverysecretkeyforaesgcm!") // 32 bytes
	plaintext := "Hello, World!"

	// Test Encryption
	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	if ciphertext == "" {
		t.Fatal("Ciphertext is empty")
	}

	if ciphertext == plaintext {
		t.Fatal("Ciphertext should not match plaintext")
	}

	// Test Decryption
	decrypted, err := Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Expected %s, got %s", plaintext, decrypted)
	}
}

func TestEncryptUniqueness(t *testing.T) {
	key := []byte("thisisaveverysecretkeyforaesgcm!")
	plaintext := "Hello, World!"

	c1, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatal(err)
	}

	c2, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatal(err)
	}

	if c1 == c2 {
		t.Error("Encryption should produce different outputs for same input (nonce usage)")
	}
}

func TestInvalidKey(t *testing.T) {
	key := []byte("shortkey")
	_, err := Encrypt("test", key)
	if err == nil {
		t.Error("Expected error with invalid key size")
	}
}

func TestDecryptInvalidData(t *testing.T) {
	key := []byte("thisisaveverysecretkeyforaesgcm!")
	
	// Test garbage data
	_, err := Decrypt("garbage", key)
	if err == nil {
		t.Error("Expected error decrypting garbage data")
	}

	// Test valid base64 but invalid ciphertext structure
	encoded := base64.StdEncoding.EncodeToString([]byte("short"))
	_, err = Decrypt(encoded, key)
	if err == nil {
		t.Error("Expected error decrypting short data")
	}
}
