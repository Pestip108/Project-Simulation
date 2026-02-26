package routes

import (
	"github.com/Pestip108/Project-Simulation/backend/pkg/heap"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

// smallBodyLimit is a middleware that rejects requests whose Content-Length
// header exceeds maxBytes. It is applied to every route EXCEPT the two file
// upload routes, which legitimately accept up to 200 MB.
//
// Note: Fiber's global BodyLimit (set in fiber.Config) is a hard fasthttp
// limit enforced at the TCP layer before any middleware runs — it cannot be
// overridden per-route. We keep the global at 200 MB so uploads are never
// dropped at the wire level, and use this middleware as an application-layer
// guard for all other routes.
func smallBodyLimit(maxBytes int64) fiber.Handler {
	return func(c *fiber.Ctx) error {
		cl := int64(c.Request().Header.ContentLength())
		// ContentLength() returns -1 when the header is missing; we allow
		// those through (chunked transfers etc.) and let normal parsing handle them.
		if cl > maxBytes {
			return c.Status(fiber.StatusRequestEntityTooLarge).JSON(fiber.Map{
				"error": "Request body too large",
			})
		}
		return c.Next()
	}
}

// SetupRoutes configures all API and page routes.
func SetupRoutes(app *fiber.App, db *gorm.DB, encryptionKey []byte, scheduler *heap.SecretScheduler) {
	// Soft body-size cap for every non-upload API route (1 MB).
	const smallLimit = int64(1 * 1024 * 1024)
	// Upload routes accept up to 200 MB; they do NOT use smallBodyLimit.
	const uploadLimit = int64(200 * 1024 * 1024)

	// ── JSON API routes ──────────────────────────────────────────────────
	api := app.Group("/api")

	// Upload: no small-limit middleware. Instead, enforce the upload cap.
	api.Post("/share", smallBodyLimit(uploadLimit), createSecretHandler(db, encryptionKey, scheduler))

	// All other API routes: enforce the 1 MB soft cap.
	api.Post("/view/:id", smallBodyLimit(smallLimit), viewSecretHandler(db, encryptionKey, scheduler))
	api.Get("/metrics", smallBodyLimit(smallLimit), metricsHandler(db))

	// ── HTML page routes (no JS) ─────────────────────────────────────────
	app.Get("/", smallBodyLimit(smallLimit), indexPageHandler())

	// Upload: no small-limit middleware; enforce the upload cap instead.
	app.Post("/share", smallBodyLimit(uploadLimit), sharePageHandler(db, encryptionKey, scheduler))

	// View secret routes: enforce the 1 MB soft cap.
	app.Get("/view/:id", smallBodyLimit(smallLimit), viewPageHandler())
	app.Post("/view/:id", smallBodyLimit(smallLimit), submitViewPageHandler(db, encryptionKey, scheduler))
}
