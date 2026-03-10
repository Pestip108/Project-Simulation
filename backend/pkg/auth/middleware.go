package auth

import (
	"github.com/Pestip108/Project-Simulation/backend/pkg/models"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

// AuthenticateMiddleware checks if the request has a valid session token
// Returns a 401 Unauthorized if not authenticated
func AuthenticateMiddleware(db *gorm.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		sessionToken := c.Cookies("session_token")
		if sessionToken == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Authentication required",
			})
		}

		var user models.User
		if result := db.Where("session_token = ?", sessionToken).First(&user); result.Error != nil {
			// Clear invalid cookie
			c.Cookie(&fiber.Cookie{
				Name:   "session_token",
				Value:  "",
				MaxAge: -1,
			})
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid or expired session",
			})
		}

		// Store user in context for downstream handlers
		c.Locals("user", user)

		return c.Next()
	}
}

// OptionalAuthMiddleware checks for a session token but doesn't fail if absent.
// This is useful for routes where both anonymous and authenticated users are allowed.
func OptionalAuthMiddleware(db *gorm.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		sessionToken := c.Cookies("session_token")
		if sessionToken != "" {
			var user models.User
			if result := db.Where("session_token = ?", sessionToken).First(&user); result.Error == nil {
				// Store user in context
				c.Locals("user", user)
			}
		}

		return c.Next()
	}
}
