package routes

import (
	"github.com/Pestip108/Project-Simulation/backend/pkg/heap"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

// SetupRoutes configures all API routes
func SetupRoutes(app *fiber.App, db *gorm.DB, encryptionKey []byte, scheduler *heap.SecretScheduler) {
	api := app.Group("/api")

	// Create a new secret
	api.Post("/share", createSecretHandler(db, encryptionKey, scheduler))

	// View a secret (and delete it)
	api.Post("/view/:id", viewSecretHandler(db, encryptionKey, scheduler))

	// Get memory metrics
	api.Get("/metrics", metricsHandler(db))
}
