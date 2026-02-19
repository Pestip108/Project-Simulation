package routes

import (
	"github.com/Pestip108/Project-Simulation/backend/pkg/heap"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

// SetupRoutes configures all API and page routes
func SetupRoutes(app *fiber.App, db *gorm.DB, encryptionKey []byte, scheduler *heap.SecretScheduler) {
	// ── JSON API routes (unchanged) ──────────────────────────────────────
	api := app.Group("/api")
	api.Post("/share", createSecretHandler(db, encryptionKey, scheduler))
	api.Post("/view/:id", viewSecretHandler(db, encryptionKey, scheduler))
	api.Get("/metrics", metricsHandler(db))

	// ── HTML page routes (no JS) ─────────────────────────────────────────
	// Home: show the create-secret form
	app.Get("/", indexPageHandler())

	// Handle form submission from the home page → create secret → show link
	app.Post("/share", sharePageHandler(db, encryptionKey, scheduler))

	// View secret: show the password form (GET) or decrypt & display (POST)
	app.Get("/view/:id", viewPageHandler())
	app.Post("/view/:id", submitViewPageHandler(db, encryptionKey, scheduler))
}
