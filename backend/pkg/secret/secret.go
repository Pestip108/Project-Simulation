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
	Text         string    `json:"text"`     // encrypted text
	IsFile       bool      `json:"isFile"`   // still useful for JSON API flags
	FileName     string    `json:"fileName"` // name of file if present
	FileContent  []byte    `json:"-"`        // encrypted file binary
	FileNonce    []byte    `json:"-"`        // nonce for file part
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	DeletedAt    time.Time `json:"deleted_at"`
	PasswordHash string    `json:"-"`
	Nonce        []byte    `json:"nonce"`    // nonce for text part
}

// BeforeCreate is a GORM hook to generate a UUID before creating a record
func (s *Secret) BeforeCreate(tx *gorm.DB) (err error) {
	if s.UUID == "" {
		s.UUID = uuid.New().String()
	}
	return
}
