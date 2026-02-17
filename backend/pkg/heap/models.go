package heap

import (
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type SecretItem struct {
	ID        uuid.UUID
	ExpiresAt time.Time
	index     int // required by heap.Interface
}

type SecretHeap []*SecretItem

type SecretScheduler struct {
	db       *gorm.DB
	heap     SecretHeap
	mutex    sync.Mutex
	cond     *sync.Cond
	indexMap map[uuid.UUID]*SecretItem
}
