package models

import (
	"time"
)

type Log struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Action    string    `json:"action"`
	Timestamp int64     `json:"timestamp"`
	CreatedAt time.Time `json:"created_at"`
}
