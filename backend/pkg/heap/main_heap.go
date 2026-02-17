package heap

import (
	"container/heap"
	"log"
	"os"
	"sync"
	"time"

	"github.com/Pestip108/Project-Simulation/backend/pkg/secret"
	"gorm.io/gorm"
)

type SecretItem struct {
	ID        int64
	ExpiresAt time.Time
	index     int // required by heap.Interface
}

type SecretHeap []*SecretItem

func (h SecretHeap) Len() int           { return len(h) }
func (h SecretHeap) Less(i, j int) bool { return h[i].ExpiresAt.Before(h[j].ExpiresAt) }
func (h SecretHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *SecretHeap) Push(x any) {
	item := x.(*SecretItem)
	item.index = len(*h)
	*h = append(*h, item)
}

func (h *SecretHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	old[n-1] = nil // avoid memory leak
	item.index = -1
	*h = old[0 : n-1]
	return item
}

// -------------------- Scheduler --------------------

type SecretScheduler struct {
	db       *gorm.DB
	heap     SecretHeap
	mutex    sync.Mutex
	cond     *sync.Cond
	indexMap map[int64]*SecretItem
}

func NewSecretScheduler(db *gorm.DB) *SecretScheduler {
	s := &SecretScheduler{
		db:       db,
		indexMap: make(map[int64]*SecretItem),
	}
	s.cond = sync.NewCond(&s.mutex)
	heap.Init(&s.heap)
	go s.run()
	return s
}

// AddSecret schedules a secret for expiry
func (s *SecretScheduler) AddSecret(id int64, expiresAt time.Time) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.indexMap[id]; exists {
		return // already scheduled
	}

	item := &SecretItem{ID: id, ExpiresAt: expiresAt}
	heap.Push(&s.heap, item)
	s.indexMap[id] = item
	s.cond.Signal() // wake up scheduler if this is the earliest expiry
}

// RemoveSecret removes a secret dynamically (e.g., consumed on read)
func (s *SecretScheduler) RemoveSecret(id int64) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	item, ok := s.indexMap[id]
	if !ok {
		return // not found
	}

	heap.Remove(&s.heap, item.index)
	delete(s.indexMap, id)
}

// -------------------- Scheduler Loop --------------------

func (s *SecretScheduler) run() {
	for {
		s.mutex.Lock()

		for s.heap.Len() == 0 {
			s.cond.Wait() // wait for secrets to be added
		}

		next := s.heap[0]
		now := time.Now()
		if now.Before(next.ExpiresAt) {
			// Sleep until next expiry or until new secret is added
			wait := time.Until(next.ExpiresAt)
			timer := time.NewTimer(wait)
			s.mutex.Unlock()

			<-timer.C
			timer.Stop()
			s.mutex.Lock()
		}

		// Remove all expired secrets
		for s.heap.Len() > 0 && !time.Now().Before(s.heap[0].ExpiresAt) {
			expired := heap.Pop(&s.heap).(*SecretItem)
			delete(s.indexMap, expired.ID)

			appDebug := os.Getenv("APPDEBUG")
			if appDebug == "" {
				log.Fatal("APPDEBUG not set")
			}

			if appDebug == "0" {
				if err := s.db.Delete(secret.Secret{}, "id = ?", expired.ID).Error; err != nil {
					log.Printf("Failed to delete secret %d: %v", expired.ID, err)
				} else {
					log.Printf("Deleted expired secret %d", expired.ID)
				}
			} else {
				if result := s.db.Model(&secret.Secret{}).Where("id = ?", expired.ID).
					Update("deleted_at", time.Now().UTC()); result.Error != nil {
					log.Printf("Failed to mark secret deleted %d: %v", expired.ID, result.Error)
				} else {
					log.Printf("Soft-Deleted expired secret %d", expired.ID)
				}
			}
		}

		s.mutex.Unlock()
	}
}

// -------------------- Reschedule after app restart --------------------

// LoadPendingSecrets loads unexpired secrets from DB and schedules them
func (s *SecretScheduler) LoadPendingSecrets() error {
	now := time.Now().UTC()

	// Delete secrets that already expired while server was down
	appDebug := os.Getenv("APPDEBUG")
	if appDebug == "" {
		log.Fatal("APPDEBUG not set")
	}

	if appDebug == "0" {
		if err := s.db.
			Where("expires_at <= ?", now).
			Delete(&secret.Secret{}).Error; err != nil {
			return err
		}
	} else {
		if err := s.db.Model(&secret.Secret{}).Where("expires_at <= ?", now).
			Update("deleted_at", time.Now().UTC()).Error; err != nil {
			return err
		}
	}

	var secrets []secret.Secret
	if err := s.db.Where("expires_at > ?", time.Now().UTC()).Find(&secrets).Error; err != nil {
		return err
	}

	for _, sec := range secrets {
		s.AddSecret(sec.ID, sec.ExpiresAt)
	}
	return nil
}
