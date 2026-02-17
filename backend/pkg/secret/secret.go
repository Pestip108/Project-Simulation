package secret

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Secret represents the data model for our shared text
type Secret struct {
	ID           string    `gorm:"primaryKey" json:"id"`
	Text         string    `json:"text"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	PasswordHash string    `json:"-"`
	Nonce        []byte    `json:"nonce"`
}

// BeforeCreate is a GORM hook to generate a UUID before creating a record
func (s *Secret) BeforeCreate(tx *gorm.DB) (err error) {
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	return
}
