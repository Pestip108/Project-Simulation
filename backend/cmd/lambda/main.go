package main

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	template "github.com/Pestip108/Project-Simulation/backend"
	"github.com/Pestip108/Project-Simulation/backend/pkg/heap"
	"github.com/Pestip108/Project-Simulation/backend/pkg/logs"
	log_listener "github.com/Pestip108/Project-Simulation/backend/pkg/logs_listener"
	"github.com/Pestip108/Project-Simulation/backend/pkg/models"
	"github.com/Pestip108/Project-Simulation/backend/pkg/routes"
	"github.com/Pestip108/Project-Simulation/backend/pkg/secret"
	"github.com/Pestip108/Project-Simulation/backend/pkg/storage"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	fiberadapter "github.com/awslabs/aws-lambda-go-api-proxy/fiber"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/gofiber/template/html/v2"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var (
	fiberLambda   *fiberadapter.FiberLambda
	encryptionKey []byte
	initOnce      sync.Once
	initErr       error
)

// SetupApp initializes Fiber, DB, scheduler, and S3
func SetupApp() (*fiber.App, error) {
	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") == "" { // local dev
		_ = godotenv.Load()
	}

	key := os.Getenv("ENCRYPTION_KEY")
	if key == "" {
		return nil, fmt.Errorf("ENCRYPTION_KEY not set")
	}
	encryptionKey = []byte(key)

	dsn := os.Getenv("DATABASE_DSN")
	if dsn == "" {
		return nil, fmt.Errorf("DATABASE_DSN not set")
	}

	redisAddress := os.Getenv("REDIS_ADDRESS")
	if redisAddress == "" {
		return nil, fmt.Errorf("REDIS_ADDRESS not set")
	}

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to DB: %w", err)
	}

	if err := db.AutoMigrate(
		&secret.Secret{},
		&models.User{},
		&models.Log{},
	); err != nil {
		return nil, fmt.Errorf("failed to auto-migrate: %w", err)
	}

	// DB connection pooling
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(10)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(time.Hour)

	scheduler := heap.NewSecretScheduler(db)
	if err := scheduler.LoadPendingSecrets(); err != nil {
		log.Println("Warning: failed to load pending secrets:", err)
	}

	// Initialize S3 Bucket
	storage.InitS3()

	// Starting logger
	// log.Println("Starting up logger...")
	rdb := redis.NewClient(&redis.Options{
		Addr: redisAddress,
	})
	logs.InitPublisher(rdb)
	go log_listener.RunLogSubscriber(rdb, db)

	// Embedded templates
	viewsSubFS, err := fs.Sub(template.ViewsFS, "views")
	if err != nil {
		return nil, fmt.Errorf("failed to create views sub-FS: %w", err)
	}

	app := fiber.New(fiber.Config{
		Views:        html.NewFileSystem(http.FS(viewsSubFS), ".html"),
		BodyLimit:    6 * 1024 * 1024, // 6MB for Lambda
		ReadTimeout:  1 * time.Minute,
		WriteTimeout: 1 * time.Minute,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if e, ok := err.(*fiber.Error); ok && e.Code == fiber.StatusRequestEntityTooLarge {
				return c.Status(fiber.StatusRequestEntityTooLarge).Render("index", fiber.Map{
					"Error": "Content is too long (max 6MB)",
				})
			}
			return fiber.DefaultErrorHandler(c, err)
		},
	})

	staticSubFS, err := fs.Sub(template.StaticFS, "static")
	if err != nil {
		log.Fatal("Failed to create static sub-filesystem:", err)
	}
	app.Use("/static", filesystem.New(filesystem.Config{
		Root: http.FS(staticSubFS),
	}))

	routes.SetupRoutes(app, db, encryptionKey, scheduler)
	return app, nil
}

// LazyInit ensures the Fiber app is initialized once
func LazyInit() error {
	initOnce.Do(func() {
		app, err := SetupApp()
		if err != nil {
			initErr = err
			return
		}
		fiberLambda = fiberadapter.New(app)
	})
	return initErr
}

// Handler is the Lambda entry point
func Handler(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	if err := LazyInit(); err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       "Failed to initialize Lambda: " + err.Error(),
		}, nil
	}

	return fiberLambda.ProxyWithContext(ctx, req)
}

func main() {
	lambda.Start(Handler)
}
