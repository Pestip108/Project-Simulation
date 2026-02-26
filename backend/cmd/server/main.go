package main

import (
	"io/fs"
	"log"
	"net/http"
	"os"
	"time"

	template "github.com/Pestip108/Project-Simulation/backend"
	"github.com/Pestip108/Project-Simulation/backend/pkg/heap"
	"github.com/Pestip108/Project-Simulation/backend/pkg/routes"
	"github.com/Pestip108/Project-Simulation/backend/pkg/secret"
	"github.com/Pestip108/Project-Simulation/backend/pkg/storage"
	"github.com/glebarez/sqlite"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/template/html/v2"
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
	db, err := gorm.Open(sqlite.Open("data/secrets.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Auto Migrate the schema
	if err := db.AutoMigrate(&secret.Secret{}); err != nil {
		log.Fatal("Failed to auto migrate:", err)
	}

	// Start the cleanup scheduler
	scheduler := heap.NewSecretScheduler(db)

	log.Println("Initializing MinIO connection...")
	storage.InitMinIO()

	// Parse custom CORS origins from .env
	if err := scheduler.LoadPendingSecrets(); err != nil {
		log.Fatal(err)
	}

	// Strip the "views/" prefix from the embedded FS so that templates
	// are registered as "index" and "view" (not "views/index", "views/view").
	viewsSubFS, err := fs.Sub(template.ViewsFS, "views")
	if err != nil {
		log.Fatal("Failed to create views sub-filesystem:", err)
	}

	// Initialize Fiber app with template engine
	app := fiber.New(fiber.Config{
		Views:        html.NewFileSystem(http.FS(viewsSubFS), ".html"),
		BodyLimit:    200 * 1024 * 1024, // 200MB hard limit (upload route needs this); non-upload routes enforce a smaller soft limit via middleware
		ReadTimeout:  1 * time.Minute,
		WriteTimeout: 1 * time.Minute,
	})

	// Configure CORS for the JSON API routes
	app.Use("/api", cors.New(cors.Config{
		AllowOrigins: allowedOrigins,
		AllowHeaders: "Origin, Content-Type, Accept",
	}))

	// Setup Rate Limit
	appDebug := os.Getenv("APPDEBUG")
	if appDebug == "" {
		log.Fatal("APPDEBUG not set")
	}

	if appDebug == "0" {
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
	}

	// Setup routes (API + page routes)
	routes.SetupRoutes(app, db, encryptionKey, scheduler)

	// Serve embedded static files (CSS, etc.) from the binary
	staticSubFS, err := fs.Sub(template.StaticFS, "static")
	if err != nil {
		log.Fatal("Failed to create static sub-filesystem:", err)
	}
	app.Use("/static", filesystem.New(filesystem.Config{
		Root: http.FS(staticSubFS),
	}))

	log.Fatal(app.Listen(":" + port))
}
