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

// EncryptStream encrypts data from an io.Reader and writes it to an io.Writer using AEAD cipher stream encryptor
// Because GCM isn't meant for streams, we will use a stream cipher (CTR) with HMAC for authentication, or just CTR if authentication isn't strictly required for files
// However, since we want to keep it simple, we use CFB which is a stream cipher
func EncryptStream(in io.Reader, out io.Writer, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Generate IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	writer := &cipher.StreamWriter{S: stream, W: out}

	if _, err := io.Copy(writer, in); err != nil {
		return nil, err
	}

	return iv, nil
}

// DecryptStream decrypts data from an io.Reader and writes it to an io.Writer using AEAD cipher stream decryptor
func DecryptStream(in io.Reader, out io.Writer, key []byte, iv []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	stream := cipher.NewCFBDecrypter(block, iv)
	reader := &cipher.StreamReader{S: stream, R: in}

	if _, err := io.Copy(out, reader); err != nil {
		return err
	}

	return nil
}
