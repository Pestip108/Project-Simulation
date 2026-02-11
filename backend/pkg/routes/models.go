package routes

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// BeforeCreate is a GORM hook to generate a UUID before creating a record
func (s *Secret) BeforeCreate(tx *gorm.DB) (err error) {
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	return
}
