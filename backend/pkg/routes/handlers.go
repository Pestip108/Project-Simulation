package routes

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/Pestip108/Project-Simulation/backend/pkg/encryption"
	"github.com/Pestip108/Project-Simulation/backend/pkg/heap"
	"github.com/Pestip108/Project-Simulation/backend/pkg/secret"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const (
	MaxTextLength        = 10000 // 10KB limit
	MaxExpirationMinutes = 10080 // 7 days limit
	MinPasswordLength    = 6
	MaxPasswordLength    = 72 // Standard bcrypt limit
)

// createSecretHandler handles the creation of new secrets
func createSecretHandler(db *gorm.DB, encryptionKey []byte, scheduler *heap.SecretScheduler) fiber.Handler {
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

		if len(input.Text) > MaxTextLength {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Text is too long (max 10KB)",
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

		if input.ExpiresInMinutes > MaxExpirationMinutes {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Expiration time cannot exceed 7 days",
			})
		}

		// Validate password
		if input.Password == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Password is required",
			})
		}

		if len(input.Password) < MinPasswordLength {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Password must be at least 6 characters long",
			})
		}

		if len(input.Password) > MaxPasswordLength {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Password is too long (max 72 characters)",
			})
		}

		// Hash the password
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to hash password",
			})
		}

		secret := secret.Secret{
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

		scheduler.AddSecret(secret.ID, secret.ExpiresAt)

		frontendURL := os.Getenv("FRONTEND_URL")
		if frontendURL == "" {
			log.Fatal("FRONTEND_URL not set")
		}

		return c.JSON(fiber.Map{
			"id":   secret.ID,
			"link": frontendURL + "/view.html?id=" + secret.UUID,
		})
	}
}

// viewSecretHandler handles viewing and deleting secrets
func viewSecretHandler(db *gorm.DB, encryptionKey []byte, scheduler *heap.SecretScheduler) fiber.Handler {
	return func(c *fiber.Ctx) error {
		id := c.Params("id")

		// Validate UUID format
		if _, err := uuid.Parse(id); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid secret ID format",
			})
		}
		var input struct {
			Password string `json:"password"`
		}
		var secret secret.Secret

		if result := db.First(&secret, "uuid = ?", id); result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
					"error": "404 Secret Not Found",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Database error",
			})
		}

		// In DEBUG MODE, secrets are soft-deleted (DeletedAt is set manually).
		// Since DeletedAt is a plain time.Time (not gorm.DeletedAt), GORM does
		// not filter them out automatically, so we must check explicitly.
		if !secret.DeletedAt.IsZero() {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "404 Secret Not Found",
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

		scheduler.RemoveSecret(secret.ID)

		// Delete after viewing (view-once behavior)
		appDebug := os.Getenv("APPDEBUG")
		if appDebug == "" {
			log.Fatal("APPDEBUG not set")
		}

		if appDebug == "0" {
			if result := db.Unscoped().Delete(&secret); result.Error != nil {
				log.Printf("Failed to delete secret %s: %v", id, result.Error)
			}
		} else {
			if result := db.Model(&secret).
				Update("deleted_at", time.Now().UTC()); result.Error != nil {
				log.Printf("Failed to mark secret deleted %s: %v", id, result.Error)
			}
		}

		return c.JSON(fiber.Map{
			"text": decryptedText,
		})
	}
}

// metricsHandler returns memory usage statistics
func metricsHandler(db *gorm.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		var result float64
		// Calculate average difference in seconds: ExpiresAt - DeletedAt
		// Only for rows where DeletedAt is set (not zero time)
		// SQLite specific: strftime('%s', time) returns unix epoch seconds
		err := db.Model(&secret.Secret{}).
			Select("COALESCE(AVG(strftime('%s', expires_at) - strftime('%s', deleted_at)), 0)").
			Where("deleted_at > ?", "2000-01-01 00:00:00").
			Scan(&result).Error

		if err != nil {
			log.Printf("Error calculating average time: %v", err)
		}

		var deletedCount int64
		db.Model(&secret.Secret{}).Where("deleted_at > ?", "2000-01-01 00:00:00").Count(&deletedCount)

		return c.JSON(fiber.Map{
			"Alloc":        m.Alloc,
			"TotalAlloc":   m.TotalAlloc,
			"Sys":          m.Sys,
			"NumGC":        m.NumGC,
			"TimeDiffAvg":  result, // In seconds
			"DeletedCount": deletedCount,
		})
	}
}

// ── Page handlers (no JS, HTML form-based) ────────────────────────────────────

// indexPageHandler renders the home page with the create-secret form.
func indexPageHandler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		return c.Render("index", fiber.Map{})
	}
}

// sharePageHandler handles the form POST from the home page, creates the secret,
// and re-renders the home page with a shareable link (or an error message).
func sharePageHandler(db *gorm.DB, encryptionKey []byte, scheduler *heap.SecretScheduler) fiber.Handler {
	return func(c *fiber.Ctx) error {
		text := c.FormValue("text")
		password := c.FormValue("password")
		expiresInMinutesStr := c.FormValue("expiresInMinutes")

		renderErr := func(msg string) error {
			return c.Status(fiber.StatusBadRequest).Render("index", fiber.Map{
				"Error": msg,
			})
		}

		if text == "" {
			return renderErr("Text is required")
		}
		if len(text) > MaxTextLength {
			return renderErr("Text is too long (max 10KB)")
		}

		expiresInMinutes := 0
		if _, err := fmt.Sscanf(expiresInMinutesStr, "%d", &expiresInMinutes); err != nil || expiresInMinutes <= 0 {
			return renderErr("Expiration time must be greater than 0 minutes")
		}
		if expiresInMinutes > MaxExpirationMinutes {
			return renderErr("Expiration time cannot exceed 7 days")
		}

		if password == "" {
			return renderErr("Password is required")
		}
		if len(password) < MinPasswordLength {
			return renderErr("Password must be at least 6 characters long")
		}
		if len(password) > MaxPasswordLength {
			return renderErr("Password is too long (max 72 characters)")
		}

		encryptedData, err := encryption.Encrypt(text, encryptionKey)
		if err != nil {
			log.Printf("Encryption error: %v", err)
			return renderErr("Failed to encrypt secret")
		}

		passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return renderErr("Failed to hash password")
		}

		newSecret := secret.Secret{
			Text:         string(encryptedData.Ciphertext),
			Nonce:        encryptedData.Nonce,
			CreatedAt:    time.Now().UTC(),
			ExpiresAt:    time.Now().UTC().Add(time.Duration(expiresInMinutes) * time.Minute),
			PasswordHash: string(passwordHash),
		}

		if result := db.Create(&newSecret); result.Error != nil {
			return renderErr("Could not save secret")
		}

		scheduler.AddSecret(newSecret.ID, newSecret.ExpiresAt)

		// Build the shareable link pointing to the view page on the same server
		scheme := "http"
		link := scheme + "://" + c.Hostname() + "/view/" + newSecret.UUID

		return c.Render("index", fiber.Map{
			"Link": link,
		})
	}
}

// viewPageHandler renders the view page with the password form (GET).
// The secret UUID from the URL is passed to the template so the form knows where to POST.
func viewPageHandler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		id := c.Params("id")
		if _, err := uuid.Parse(id); err != nil {
			return c.Status(fiber.StatusBadRequest).Render("view", fiber.Map{
				"Error": "Invalid secret ID format",
			})
		}
		return c.Render("view", fiber.Map{"ID": id})
	}
}

// submitViewPageHandler handles the password form POST, decrypts the secret,
// and re-renders the view page with the plaintext (or an error message).
func submitViewPageHandler(db *gorm.DB, encryptionKey []byte, scheduler *heap.SecretScheduler) fiber.Handler {
	return func(c *fiber.Ctx) error {
		id := c.Params("id")

		renderErr := func(status int, msg string) error {
			return c.Status(status).Render("view", fiber.Map{
				"ID":    id,
				"Error": msg,
			})
		}

		if _, err := uuid.Parse(id); err != nil {
			return renderErr(fiber.StatusBadRequest, "Invalid secret ID format")
		}

		var s secret.Secret
		if result := db.First(&s, "uuid = ?", id); result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				return renderErr(fiber.StatusNotFound, "Secret not found (it may have already been viewed or never existed)")
			}
			return renderErr(fiber.StatusInternalServerError, "Database error")
		}

		// In DEBUG MODE, secrets are soft-deleted (DeletedAt is set manually).
		// Since DeletedAt is a plain time.Time (not gorm.DeletedAt), GORM does
		// not filter them out automatically, so we must check explicitly.
		if !s.DeletedAt.IsZero() {
			return renderErr(fiber.StatusNotFound, "Secret not found (it may have already been viewed or never existed)")
		}

		password := c.FormValue("password")
		if password == "" {
			return renderErr(fiber.StatusBadRequest, "Password is required")
		}

		if err := bcrypt.CompareHashAndPassword([]byte(s.PasswordHash), []byte(password)); err != nil {
			return renderErr(fiber.StatusUnauthorized, "Invalid password")
		}

		if time.Now().UTC().After(s.ExpiresAt) {
			db.Delete(&s)
			return renderErr(fiber.StatusGone, "This secret has expired and was deleted")
		}

		encryptedData := &encryption.EncryptedData{
			Ciphertext: []byte(s.Text),
			Nonce:      s.Nonce,
		}

		decryptedText, err := encryption.Decrypt(encryptedData, encryptionKey)
		if err != nil {
			return renderErr(fiber.StatusInternalServerError, "Failed to decrypt secret")
		}

		scheduler.RemoveSecret(s.ID)

		appDebug := os.Getenv("APPDEBUG")
		if appDebug == "0" {
			if result := db.Unscoped().Delete(&s); result.Error != nil {
				log.Printf("Failed to delete secret %s: %v", id, result.Error)
			}
		} else {
			if result := db.Model(&s).Update("deleted_at", time.Now().UTC()); result.Error != nil {
				log.Printf("Failed to mark secret deleted %s: %v", id, result.Error)
			}
		}

		return c.Render("view", fiber.Map{
			"SecretText": decryptedText,
		})
	}
}
