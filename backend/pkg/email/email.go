package email

import (
	"fmt"
	"net/smtp"
	"os"
)

// SendVerificationEmail sends an email with a verification link
func SendVerificationEmail(toEmail, token string) error {
	smtpHost := os.Getenv("SMTP_HOST")
	if smtpHost == "" {
		smtpHost = "localhost" // Fallback to localhost if not set
	}

	smtpPort := os.Getenv("SMTP_PORT")
	if smtpPort == "" {
		smtpPort = "1025" // Fallback to mailpit default
	}

	port := os.Getenv("PORT")
	if port == "" {
		return fmt.Errorf("PORT environment variable is not set")
	}

	backendBaseUrl := os.Getenv("BACKEND_BASE_URL")
	if backendBaseUrl == "" {
		return fmt.Errorf("BACKEND_BASE_URL environment variable is not set")
	}

	// For local testing with Mailpit, we don't need authentication
	from := "noreply@shareasecret.local"
	to := []string{toEmail}

	verificationLink := fmt.Sprintf("%s:%s/api/verify?token=%s", backendBaseUrl, port, token)

	message := []byte("Subject: Verify your email address\r\n" +
		"\r\n" +
		"Please click the following link to verify your email address:\r\n" +
		verificationLink + "\r\n")

	err := smtp.SendMail(smtpHost+":"+smtpPort, nil, from, to, message)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}
