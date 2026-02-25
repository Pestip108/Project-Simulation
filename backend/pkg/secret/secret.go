package secret

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Secret represents the data model for our shared text
type Secret struct {
	ID           int64     `gorm:"primaryKey" json:"id"`
	UUID         string    `json:"uuid"`
	Text         string    `json:"text"`
	IsFile       bool      `json:"isFile"`
	FileName     string    `json:"fileName"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	DeletedAt    time.Time `json:"deleted_at"`
	PasswordHash string    `json:"-"`
	Nonce        []byte    `json:"nonce"`
}

// BeforeCreate is a GORM hook to generate a UUID before creating a record
func (s *Secret) BeforeCreate(tx *gorm.DB) (err error) {
	if s.UUID == "" {
		s.UUID = uuid.New().String()
	}
	return
}
