package routes

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/Pestip108/Project-Simulation/backend/pkg/encryption"
	"github.com/Pestip108/Project-Simulation/backend/pkg/heap"
	"github.com/Pestip108/Project-Simulation/backend/pkg/secret"
	"github.com/Pestip108/Project-Simulation/backend/pkg/storage"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const (
	MaxTextLength        = 10 * 1024 * 1024 // 10MB limit
	MaxExpirationMinutes = 10080            // 7 days limit
	MinPasswordLength    = 6
	MaxPasswordLength    = 72 // Standard bcrypt limit
)

// createSecretHandler handles the creation of new secrets
func createSecretHandler(db *gorm.DB, encryptionKey []byte, scheduler *heap.SecretScheduler) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var text string
		var expiresInMinutes int
		var password string
		var isFile bool
		var fileName string
		var fileContentBytes []byte

		if file, err := c.FormFile("file"); err == nil {
			isFile = true
			fileName = file.Filename

			fileContent, err := file.Open()
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": "Failed to process file",
				})
			}
			defer fileContent.Close()

			buf := new(bytes.Buffer)
			if _, err := io.Copy(buf, fileContent); err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": "Failed to read file",
				})
			}
			fileContentBytes = buf.Bytes()
		}

		// Pull from multipart form if present
		text = c.FormValue("text")
		password = c.FormValue("password")
		expiresInMinutesStr := c.FormValue("expiresInMinutes")
		fmt.Sscanf(expiresInMinutesStr, "%d", &expiresInMinutes)

		// Fallback to JSON API
		if text == "" && !isFile {
			var input struct {
				Text             string `json:"text"`
				ExpiresInMinutes int    `json:"expiresInMinutes"`
				Password         string `json:"password"`
			}
			if err := c.BodyParser(&input); err == nil {
				text = input.Text
				expiresInMinutes = input.ExpiresInMinutes
				password = input.Password
			}
		}

		if text == "" && !isFile {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Either text or a file is required",
			})
		}

		if len(text) > MaxTextLength || len(fileContentBytes) > MaxTextLength {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Content is too long (max 10MB)",
			})
		}

		var encryptedTextNonce []byte
		var encryptedTextString string
		if text != "" {
			encData, err := encryption.Encrypt([]byte(text), encryptionKey)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to encrypt text"})
			}
			encryptedTextNonce = encData.Nonce
			encryptedTextString = string(encData.Ciphertext)
		}

		var fileKey string
		var encryptedFileNonce []byte
		if isFile {
			encData, err := encryption.Encrypt(fileContentBytes, encryptionKey)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to encrypt file"})
			}

			fileKey = uuid.New().String()
			encryptedFileNonce = encData.Nonce
			opts := minio.PutObjectOptions{}
			reader := bytes.NewReader(encData.Ciphertext)

			_, err = storage.Client.PutObject(c.Context(), storage.BucketName, fileKey, reader, int64(len(encData.Ciphertext)), opts)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to upload file to MinIO"})
			}
		}

		if expiresInMinutes <= 0 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Expiration time must be greater than 0 minutes",
			})
		}

		if expiresInMinutes > MaxExpirationMinutes {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Expiration time cannot exceed 7 days",
			})
		}

		// Validate password
		if password == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Password is required",
			})
		}

		if len(password) < MinPasswordLength {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Password must be at least 6 characters long",
			})
		}

		if len(password) > MaxPasswordLength {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Password is too long (max 72 characters)",
			})
		}

		// Hash the password
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to hash password",
			})
		}

		secret := secret.Secret{
			Text:         encryptedTextString,
			FileName:     fileName,
			FileKey:      fileKey,
			TextNonce:    encryptedTextNonce,
			FileNonce:    encryptedFileNonce,
			CreatedAt:    time.Now().UTC(),
			ExpiresAt:    time.Now().UTC().Add(time.Duration(expiresInMinutes) * time.Minute),
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

		var decryptedText string
		if secret.Text != "" {
			encData := &encryption.EncryptedData{
				Ciphertext: []byte(secret.Text),
				Nonce:      secret.TextNonce,
			}
			text, err := encryption.Decrypt(encData, encryptionKey)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to decrypt text"})
			}
			decryptedText = string(text)
		}

		var fileData string
		if secret.FileKey != "" {
			obj, err := storage.Client.GetObject(c.Context(), storage.BucketName, secret.FileKey, minio.GetObjectOptions{})
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to get file from MinIO"})
			}
			defer obj.Close()

			cipherText, err := io.ReadAll(obj)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to read file from MinIO"})
			}

			encData := &encryption.EncryptedData{
				Ciphertext: cipherText,
				Nonce:      secret.FileNonce,
			}
			decBytes, err := encryption.Decrypt(encData, encryptionKey)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to decrypt file"})
			}
			fileData = base64.StdEncoding.EncodeToString([]byte(decBytes))
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
			if secret.FileKey != "" {
				_ = storage.Client.RemoveObject(context.Background(), storage.BucketName, secret.FileKey, minio.RemoveObjectOptions{})
			}
		} else {
			if result := db.Model(&secret).
				Update("deleted_at", time.Now().UTC()); result.Error != nil {
				log.Printf("Failed to mark secret deleted %s: %v", id, result.Error)
			}
		}

		return c.JSON(fiber.Map{
			"text":     decryptedText,
			"fileName": secret.FileName,
			"fileData": fileData,
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

		var isFile bool
		var fileName string
		var fileContentBytes []byte

		if fileHeader, err := c.FormFile("file"); err == nil {
			isFile = true
			fileName = fileHeader.Filename

			file, err := fileHeader.Open()
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).Render("index", fiber.Map{
					"Error": "Failed to process file",
				})
			}
			defer file.Close()

			buf := new(bytes.Buffer)
			if _, err := io.Copy(buf, file); err != nil {
				return c.Status(fiber.StatusInternalServerError).Render("index", fiber.Map{
					"Error": "Failed to read file",
				})
			}
			fileContentBytes = buf.Bytes()
		}

		renderErr := func(msg string) error {
			return c.Status(fiber.StatusBadRequest).Render("index", fiber.Map{
				"Error": msg,
			})
		}

		if text == "" && !isFile {
			return renderErr("Either text or a file is required")
		}
		if len(text) > MaxTextLength || len(fileContentBytes) > MaxTextLength {
			return renderErr("Content is too long (max 10MB)")
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

		var encryptedTextNonce []byte
		var encryptedTextString string
		if text != "" {
			encData, err := encryption.Encrypt([]byte(text), encryptionKey)
			if err != nil {
				return renderErr("Failed to encrypt text")
			}
			encryptedTextNonce = encData.Nonce
			encryptedTextString = string(encData.Ciphertext)
		}

		var fileKey string
		var encryptedFileNonce []byte
		if isFile {
			encData, err := encryption.Encrypt(fileContentBytes, encryptionKey)
			if err != nil {
				return renderErr("Failed to encrypt file")
			}
			fileKey = uuid.New().String()
			encryptedFileNonce = encData.Nonce
			opts := minio.PutObjectOptions{}
			reader := bytes.NewReader(encData.Ciphertext)

			_, err = storage.Client.PutObject(c.Context(), storage.BucketName, fileKey, reader, int64(len(encData.Ciphertext)), opts)
			if err != nil {
				return renderErr("Failed to upload file to MinIO")
			}
		}

		passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return renderErr("Failed to hash password")
		}

		newSecret := secret.Secret{
			Text:         encryptedTextString,
			FileName:     fileName,
			FileKey:      fileKey,
			TextNonce:    encryptedTextNonce,
			FileNonce:    encryptedFileNonce,
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

		var decryptedText string
		if s.Text != "" {
			encData := &encryption.EncryptedData{
				Ciphertext: []byte(s.Text),
				Nonce:      s.TextNonce,
			}
			txt, err := encryption.Decrypt(encData, encryptionKey)
			if err != nil {
				return renderErr(fiber.StatusInternalServerError, "Failed to decrypt text")
			}
			decryptedText = string(txt)
		}

		var fileData string
		if s.FileKey != "" {
			obj, err := storage.Client.GetObject(c.Context(), storage.BucketName, s.FileKey, minio.GetObjectOptions{})
			if err != nil {
				return renderErr(fiber.StatusInternalServerError, "Failed to get file from MinIO")
			}
			defer obj.Close()

			cipherText, err := io.ReadAll(obj)
			if err != nil {
				return renderErr(fiber.StatusInternalServerError, "Failed to read file from MinIO")
			}

			encData := &encryption.EncryptedData{
				Ciphertext: cipherText,
				Nonce:      s.FileNonce,
			}
			decBytes, err := encryption.Decrypt(encData, encryptionKey)
			if err != nil {
				return renderErr(fiber.StatusInternalServerError, "Failed to decrypt file")
			}
			fileData = base64.StdEncoding.EncodeToString([]byte(decBytes))
		}

		scheduler.RemoveSecret(s.ID)

		appDebug := os.Getenv("APPDEBUG")
		if appDebug == "0" {
			if result := db.Unscoped().Delete(&s); result.Error != nil {
				log.Printf("Failed to delete secret %s: %v", id, result.Error)
			}
			if s.FileKey != "" {
				_ = storage.Client.RemoveObject(context.Background(), storage.BucketName, s.FileKey, minio.RemoveObjectOptions{})
			}
		} else {
			if result := db.Model(&s).Update("deleted_at", time.Now().UTC()); result.Error != nil {
				log.Printf("Failed to mark secret deleted %s: %v", id, result.Error)
			}
		}

		isFile := s.FileKey != ""

		return c.Render("view", fiber.Map{
			"SecretText": decryptedText,
			"IsFile":     isFile,
			"FileName":   s.FileName,
			"FileData":   fileData,
		})
	}
}
