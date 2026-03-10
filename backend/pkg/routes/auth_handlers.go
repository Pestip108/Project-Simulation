package routes

import (
	"log"
	"time"

	"github.com/Pestip108/Project-Simulation/backend/pkg/auth"
	"github.com/Pestip108/Project-Simulation/backend/pkg/email"
	"github.com/Pestip108/Project-Simulation/backend/pkg/models"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

// registerHandler handles the user registration API request
func registerHandler(db *gorm.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var input struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		if err := c.BodyParser(&input); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Cannot parse JSON"})
		}

		if input.Email == "" || input.Password == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Email and password are required"})
		}

		if len(input.Password) < 6 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Password must be at least 6 characters long"})
		}

		// Check if user already exists
		var existingUser models.User
		if result := db.Where("email = ?", input.Email).First(&existingUser); result.Error == nil {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "User with this email already exists"})
		} else if result.Error != gorm.ErrRecordNotFound {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
		}

		// Hash password
		passwordHash, err := auth.HashPassword(input.Password)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to hash password"})
		}

		// Generate verification token
		verificationToken, err := auth.GenerateRandomToken(32)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate token"})
		}

		// Create user
		newUser := models.User{
			Email:             input.Email,
			PasswordHash:      passwordHash,
			IsVerified:        false,
			VerificationToken: verificationToken,
			CreatedAt:         time.Now().UTC(),
			UpdatedAt:         time.Now().UTC(),
		}

		if result := db.Create(&newUser); result.Error != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not create user"})
		}

		// Send verification email
		go func() {
			err := email.SendVerificationEmail(newUser.Email, newUser.VerificationToken)
			if err != nil {
				log.Printf("Failed to send verification email to %s: %v", newUser.Email, err)
			}
		}()

		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"message": "User registered successfully. Please check your email to verify your account.",
		})
	}
}

// registerPageHandler serves the registration HTML page
func registerPageHandler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		return c.Render("register", fiber.Map{})
	}
}

// submitRegisterPageHandler processes the form submission from the HTML register page
func submitRegisterPageHandler(db *gorm.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		emailInput := c.FormValue("email")
		password := c.FormValue("password")

		renderErr := func(msg string) error {
			return c.Status(fiber.StatusBadRequest).Render("register", fiber.Map{
				"Error": msg,
			})
		}

		if emailInput == "" || password == "" {
			return renderErr("Email and password are required")
		}

		if len(password) < 6 {
			return renderErr("Password must be at least 6 characters long")
		}

		var existingUser models.User
		if result := db.Where("email = ?", emailInput).First(&existingUser); result.Error == nil {
			return renderErr("User with this email already exists")
		} else if result.Error != gorm.ErrRecordNotFound {
			return c.Status(fiber.StatusInternalServerError).Render("register", fiber.Map{"Error": "Database error"})
		}

		passwordHash, err := auth.HashPassword(password)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).Render("register", fiber.Map{"Error": "Failed to hash password"})
		}

		verificationToken, err := auth.GenerateRandomToken(32)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).Render("register", fiber.Map{"Error": "Failed to generate token"})
		}

		newUser := models.User{
			Email:             emailInput,
			PasswordHash:      passwordHash,
			IsVerified:        false,
			VerificationToken: verificationToken,
			CreatedAt:         time.Now().UTC(),
			UpdatedAt:         time.Now().UTC(),
		}

		if result := db.Create(&newUser); result.Error != nil {
			return c.Status(fiber.StatusInternalServerError).Render("register", fiber.Map{"Error": "Could not create user"})
		}

		go func() {
			err := email.SendVerificationEmail(newUser.Email, newUser.VerificationToken)
			if err != nil {
				log.Printf("Failed to send verification email to %s: %v", newUser.Email, err)
			}
		}()

		return c.Render("register", fiber.Map{
			"Success": "Registration successful. Please check your email to verify your account.",
		})
	}
}

// verifyHandler handles email verification from the generated link
func verifyHandler(db *gorm.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := c.Query("token")

		if token == "" {
			return c.Status(fiber.StatusBadRequest).SendString("Verification token is required")
		}

		var user models.User
		if result := db.Where("verification_token = ?", token).First(&user); result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				return c.Status(fiber.StatusNotFound).SendString("Invalid or expired verification token")
			}
			return c.Status(fiber.StatusInternalServerError).SendString("Database error")
		}

		if user.IsVerified {
			return c.SendString("Account is already verified. You can now log in.")
		}

		user.IsVerified = true
		user.VerificationToken = "" // Clear the token so it can't be reused

		if result := db.Save(&user); result.Error != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Could not verify account")
		}

		return c.SendString("Account successfully verified! You can now log in to upload files.")
	}
}

// loginHandler handles the user login API request
func loginHandler(db *gorm.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var input struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		if err := c.BodyParser(&input); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Cannot parse JSON"})
		}

		var user models.User
		if result := db.Where("email = ?", input.Email).First(&user); result.Error != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
		}

		if !auth.CheckPasswordHash(input.Password, user.PasswordHash) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
		}

		if !user.IsVerified {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Email not verified. Please check your inbox."})
		}

		sessionToken, err := auth.GenerateRandomToken(64)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not generate session token"})
		}

		user.SessionToken = sessionToken
		if result := db.Save(&user); result.Error != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not save session"})
		}

		c.Cookie(&fiber.Cookie{
			Name:     "session_token",
			Value:    sessionToken,
			Expires:  time.Now().Add(24 * time.Hour),
			HTTPOnly: true,
			Secure:   false, // Set to true in production with HTTPS
			SameSite: "Lax",
		})

		return c.JSON(fiber.Map{"message": "Login successful"})
	}
}

// logoutHandler clears the session token cookie
func logoutHandler(db *gorm.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		sessionToken := c.Cookies("session_token")
		if sessionToken != "" {
			db.Model(&models.User{}).Where("session_token = ?", sessionToken).Update("session_token", "")
		}

		c.Cookie(&fiber.Cookie{
			Name:     "session_token",
			Value:    "",
			Expires:  time.Now().Add(-1 * time.Hour), // Expire the cookie
			HTTPOnly: true,
			Secure:   false,
			SameSite: "Lax",
		})

		// Return regular redirect for page requests, or JSON for API
		if c.Get("Accept") != "application/json" && c.Path() == "/logout" {
			return c.Redirect("/")
		}

		return c.JSON(fiber.Map{"message": "Logged out successfully"})
	}
}

// loginPageHandler serves the login HTML page
func loginPageHandler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		return c.Render("login", fiber.Map{})
	}
}

// submitLoginPageHandler processes the form submission from the HTML login page
func submitLoginPageHandler(db *gorm.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		emailInput := c.FormValue("email")
		password := c.FormValue("password")

		renderErr := func(msg string) error {
			return c.Status(fiber.StatusUnauthorized).Render("login", fiber.Map{
				"Error": msg,
			})
		}

		if emailInput == "" || password == "" {
			return renderErr("Email and password are required")
		}

		var user models.User
		if result := db.Where("email = ?", emailInput).First(&user); result.Error != nil {
			return renderErr("Invalid credentials")
		}

		if !auth.CheckPasswordHash(password, user.PasswordHash) {
			return renderErr("Invalid credentials")
		}

		if !user.IsVerified {
			return c.Status(fiber.StatusForbidden).Render("login", fiber.Map{"Error": "Email not verified. Please check your inbox for the verification link."})
		}

		sessionToken, err := auth.GenerateRandomToken(64)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).Render("login", fiber.Map{"Error": "Server error generating session"})
		}

		user.SessionToken = sessionToken
		if result := db.Save(&user); result.Error != nil {
			return c.Status(fiber.StatusInternalServerError).Render("login", fiber.Map{"Error": "Server error saving session"})
		}

		c.Cookie(&fiber.Cookie{
			Name:     "session_token",
			Value:    sessionToken,
			Expires:  time.Now().Add(24 * time.Hour),
			HTTPOnly: true,
			Secure:   false,
			SameSite: "Lax",
		})

		return c.Redirect("/")
	}
}
