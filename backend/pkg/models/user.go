package models

import (
	"time"
)

// User represents a registered user in the system
type User struct {
	ID                uint      `gorm:"primaryKey" json:"id"`
	Email             string    `gorm:"uniqueIndex;not null" json:"email"`
	PasswordHash      string    `gorm:"not null" json:"-"`
	IsVerified        bool      `gorm:"default:false" json:"isVerified"`
	VerificationToken string    `json:"-"`
	SessionToken      string    `gorm:"index" json:"-"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
}
