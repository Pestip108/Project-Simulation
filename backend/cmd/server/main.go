package main

import (
	"log"
	"os"
	"time"

	"github.com/Pestip108/Project-Simulation/backend/pkg/encryption"
	"github.com/glebarez/sqlite"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Secret represents the data model for our shared text
type Secret struct {
	ID        string    `gorm:"primaryKey" json:"id"`
	Text      string    `json:"text"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// BeforeCreate is a GORM hook to generate a UUID before creating a record
func (s *Secret) BeforeCreate(tx *gorm.DB) (err error) {
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	return
}

// Key for demonstration (32 bytes for AES-256)
var encryptionKey []byte

func init() {
	key := os.Getenv("ENCRYPTION_KEY")
	if key == "" {
		log.Fatal("ENCRYPTION_KEY not set")
	}

	if len(key) != 32 {
		log.Fatal("ENCRYPTION_KEY must be 32 bytes for AES-256")
	}

	encryptionKey = []byte(key)
}

func main() {
	db, err := gorm.Open(sqlite.Open("secrets.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Auto Migrate the schema
	if err := db.AutoMigrate(&Secret{}); err != nil {
		log.Fatal("Failed to auto migrate:", err)
	}

	go startCleanupJob(db)

	// Initialize Fiber app
	app := fiber.New()

	// Background worker to clean up expired secrets
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			err := db.
				Where("expires_at <= ?", time.Now().UTC()).
				Delete(&Secret{}).Error

			if err != nil {
				log.Printf("Cleanup error: %v", err)
			}
		}
	}()

	// Configure CORS
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*", // For development mostly
		AllowHeaders: "Origin, Content-Type, Accept",
	}))

	// Setup Rate Limit
	app.Use(limiter.New(limiter.Config{
		Max:        100,             // max requests
		Expiration: 1 * time.Minute, // per time window
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.IP() // limit per IP
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Too many requests. Please try again later.",
			})
		},
	}))

	// Define API routes
	api := app.Group("/api")

	// Create a new secret
	api.Post("/share", func(c *fiber.Ctx) error {
		var input struct {
			Text             string `json:"text"`
			ExpiresInMinutes int    `json:"expiresInMinutes"` // 0 means use default or never? Let's say 0 means "never" (view once only)
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
		encryptedText, err := encryption.Encrypt(input.Text, encryptionKey)
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

		secret := Secret{
			Text:      encryptedText,
			ExpiresAt: time.Now().UTC().Add(time.Duration(input.ExpiresInMinutes) * time.Minute),
		}

		if result := db.Create(&secret); result.Error != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Could not save secret",
			})
		}

		// Return the full URL for viewing (assuming localhost:3000 for now, logic can be improved)
		// Ideally the frontend constructs the URL, but returning the ID is sufficient.
		// Let's return the link as requested in plan.
		// Note: Host/Port hardcoded for MVP as per plan.
		return c.JSON(fiber.Map{
			"id":   secret.ID,
			"link": "http://localhost:3000/api/view/" + secret.ID,
		})
	})

	// View a secret (and delete it)
	api.Get("/view/:id", func(c *fiber.Ctx) error {
		id := c.Params("id")
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

		// Check expiration
		if time.Now().UTC().After(secret.ExpiresAt) {
			db.Delete(&secret)
			return c.Status(fiber.StatusGone).JSON(fiber.Map{
				"error": "Secret has expired",
			})
		}

		// Delete after viewing (view-once behavior)
		if result := db.Unscoped().Delete(&secret); result.Error != nil {
			log.Printf("Failed to delete secret %s: %v", id, result.Error)
		}

		decryptedText, err := encryption.Decrypt(secret.Text, encryptionKey)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to decrypt secret",
			})
		}

		return c.JSON(fiber.Map{
			"text": decryptedText,
		})
	})

	// Serve static files for frontend (optional, since we put them in ../../frontend)
	// But usually it's easier to serve them from root or specific path.
	// For this task, we will just start the server. The user can open HTML files directly OR we serve them.
	// Let's serve them for better experience (CORS issues with file:// protocol).
	app.Static("/", "../../frontend")

	log.Fatal(app.Listen(":3000"))
}

func startCleanupJob(db *gorm.DB) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		<-ticker.C

		result := db.Unscoped().
			Where("expires_at IS NOT NULL AND expires_at != ? AND expires_at <= ?",
				time.Time{}, time.Now()).
			Delete(&Secret{})

		if result.Error != nil {
			log.Printf("Cleanup error: %v", result.Error)
		} else if result.RowsAffected > 0 {
			log.Printf("Deleted %d expired secrets", result.RowsAffected)
		}
	}
}
