package main

import (
	"log"
	"os"
	"time"

	"github.com/Pestip108/Project-Simulation/backend/pkg/heap"
	"github.com/Pestip108/Project-Simulation/backend/pkg/routes"
	"github.com/Pestip108/Project-Simulation/backend/pkg/secret"
	"github.com/glebarez/sqlite"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/joho/godotenv"
	"gorm.io/gorm"
)

// Key for demonstration (32 bytes for AES-256)
var encryptionKey []byte
var allowedOrigins string
var port string

func init() {
	godotenv.Load()

	allowedOrigins = os.Getenv("CORS_ALLOWED_ORIGINS")
	if allowedOrigins == "" {
		log.Fatal("ALLOWED_ORIGINS not set")
	}

	port = os.Getenv("PORT")
	if port == "" {
		log.Fatal("PORT not set")
	}

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
	if err := db.AutoMigrate(&secret.Secret{}); err != nil {
		log.Fatal("Failed to auto migrate:", err)
	}

	// Initialize Scheduler
	scheduler := heap.NewSecretScheduler(db)
	if err := scheduler.LoadPendingSecrets(); err != nil {
		log.Fatal(err)
	}

	// Initialize Fiber app
	app := fiber.New()

	// Configure CORS
	app.Use(cors.New(cors.Config{
		AllowOrigins: allowedOrigins, // For development mostly
		AllowHeaders: "Origin, Content-Type, Accept",
	}))

	// Setup Rate Limit
	app.Use(limiter.New(limiter.Config{
		Max:        20,              // max requests
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

	// Setup routes
	routes.SetupRoutes(app, db, encryptionKey, scheduler)

	// Serve static files for frontend
	app.Static("/", "../../frontend")

	log.Fatal(app.Listen(":" + port))
}
