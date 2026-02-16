package routes

import (
	"log"
	"os"
	"time"

	"github.com/Pestip108/Project-Simulation/backend/pkg/encryption"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// createSecretHandler handles the creation of new secrets
func createSecretHandler(db *gorm.DB, encryptionKey []byte) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var input struct {
			Text             string `json:"text"`
			ExpiresInMinutes int    `json:"expiresInMinutes"`
			Password         string `json:"password"`
		}

		if err := c.BodyParser(&input); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Cannot parse JSON",
			})
		}

		if input.Text == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Text is required",
			})
		}

		// Encrypt the text before saving
		encryptedData, err := encryption.Encrypt(input.Text, encryptionKey)
		if err != nil {
			log.Printf("Encryption error: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to encrypt secret",
			})
		}

		if input.ExpiresInMinutes <= 0 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Expiration time must be greater than 0 minutes",
			})
		}

		// Validate password
		if input.Password == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Password is required",
			})
		}

		// Hash the password
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to hash password",
			})
		}

		secret := Secret{
			Text:         string(encryptedData.Ciphertext),
			Nonce:        encryptedData.Nonce,
			CreatedAt:    time.Now().UTC(),
			ExpiresAt:    time.Now().UTC().Add(time.Duration(input.ExpiresInMinutes) * time.Minute),
			PasswordHash: string(passwordHash)}

		if result := db.Create(&secret); result.Error != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Could not save secret",
			})
		}

		frontendURL := os.Getenv("FRONTEND_URL")
		if frontendURL == "" {
			log.Fatal("FRONTEND_URL not set")
		}

		return c.JSON(fiber.Map{
			"id":   secret.ID,
			"link": frontendURL + "/view.html?id=" + secret.ID,
		})
	}
}

// viewSecretHandler handles viewing and deleting secrets
func viewSecretHandler(db *gorm.DB, encryptionKey []byte) fiber.Handler {
	return func(c *fiber.Ctx) error {
		id := c.Params("id")
		var input struct {
			Password string `json:"password"`
		}
		var secret Secret

		if result := db.First(&secret, "id = ?", id); result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
					"error": "404 Secret Not Found",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Database error",
			})
		}

		if err := c.BodyParser(&input); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Cannot parse JSON",
			})
		}

		if input.Password == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Password required",
			})
		}

		// Check password
		err := bcrypt.CompareHashAndPassword([]byte(secret.PasswordHash), []byte(input.Password))
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid password",
			})
		}

		// Check expiration
		if time.Now().UTC().After(secret.ExpiresAt) {
			db.Delete(&secret)
			return c.Status(fiber.StatusGone).JSON(fiber.Map{
				"error": "Secret has expired",
			})
		}

		// Reconstruct EncryptedData from stored fields
		encryptedData := &encryption.EncryptedData{
			Ciphertext: []byte(secret.Text),
			Nonce:      secret.Nonce,
		}

		decryptedText, err := encryption.Decrypt(encryptedData, encryptionKey)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to decrypt secret",
			})
		}

		// Delete after viewing (view-once behavior)
		if result := db.Unscoped().Delete(&secret); result.Error != nil {
			log.Printf("Failed to delete secret %s: %v", id, result.Error)
		}

		return c.JSON(fiber.Map{
			"text": decryptedText,
		})
	}
}
