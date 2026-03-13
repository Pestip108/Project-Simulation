package models

import (
	"time"
)

// User represents a registered user in the system
type User struct {
	ID                uint      `gorm:"primaryKey" json:"id"`
	Email             string    `gorm:"size:255;uniqueIndex;not null" json:"email"`
	PasswordHash      string    `gorm:"size:255;not null" json:"-"`
	IsVerified        bool      `gorm:"default:false" json:"isVerified"`
	VerificationToken string    `gorm:"size:255" json:"-"`
	SessionToken      string    `gorm:"size:255;index" json:"-"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
}
