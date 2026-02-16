package routes

import (
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

// SetupRoutes configures all API routes
func SetupRoutes(app *fiber.App, db *gorm.DB, encryptionKey []byte) {
	api := app.Group("/api")

	// Create a new secret
	api.Post("/share", createSecretHandler(db, encryptionKey))

	// View a secret (and delete it)
	api.Post("/view/:id", viewSecretHandler(db, encryptionKey))
}
