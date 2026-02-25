package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// Encrypt encrypts plain text string into a base64 encoded string using AES-GCM with the given key.
// The key must be 16, 24, or 32 bytes long for AES-128, AES-192, or AES-256.
func Encrypt(data []byte, key []byte) (*EncryptedData, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt
	ciphertext := aesGCM.Seal(nil, nonce, data, nil)

	return &EncryptedData{
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}, nil
}

// Decrypt decrypts a base64 encoded string using AES-GCM with the given key.
func Decrypt(data *EncryptedData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Decrypt using the nonce stored in the struct
	plaintext, err := aesGCM.Open(nil, data.Nonce, data.Ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
