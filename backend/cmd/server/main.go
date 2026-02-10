package main

import (
	"log"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Secret represents the data model for our shared text
type Secret struct {
	ID        string    `gorm:"primaryKey" json:"id"`
	Text      string    `json:"text"`
	CreatedAt time.Time `json:"created_at"`
}

// BeforeCreate is a GORM hook to generate a UUID before creating a record
func (s *Secret) BeforeCreate(tx *gorm.DB) (err error) {
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	return
}

func main() {
	// Initialize GORM with SQLite
	db, err := gorm.Open(sqlite.Open("secrets.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Auto Migrate the schema
	if err := db.AutoMigrate(&Secret{}); err != nil {
		log.Fatal("Failed to auto migrate:", err)
	}

	// Initialize Fiber app
	app := fiber.New()

	// Configure CORS
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*", // For development mostly
		AllowHeaders: "Origin, Content-Type, Accept",
	}))

	// Define API routes
	api := app.Group("/api")

	// Create a new secret
	api.Post("/share", func(c *fiber.Ctx) error {
		var input struct {
			Text string `json:"text"`
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

		secret := Secret{
			Text: input.Text,
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

		// Find the secret
		if result := db.First(&secret, "id = ?", id); result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
					"error": "Secret not found or already viewed",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Database error",
			})
		}

		// Delete the secret (Hard delete because we don't want to keep it)
		if result := db.Unscoped().Delete(&secret); result.Error != nil {
			// If delete fails, we should probably warn or log, but user still gets the data?
			// Ideally transaction.
			log.Printf("Failed to delete secret %s: %v", id, result.Error)
		}

		return c.JSON(fiber.Map{
			"text": secret.Text,
		})
	})

	// Serve static files for frontend (optional, since we put them in ../../frontend)
	// But usually it's easier to serve them from root or specific path.
	// For this task, we will just start the server. The user can open HTML files directly OR we serve them.
	// Let's serve them for better experience (CORS issues with file:// protocol).
	app.Static("/", "../../frontend")

	log.Fatal(app.Listen(":3000"))
}
