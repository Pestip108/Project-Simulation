package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/joho/godotenv"
)

const (
	TotalRequests = 500000
	Workers       = 50
)

var (
	successCount uint64
	failCount    uint64
)

func main() {
	// Try to load .env from backend folder
	godotenv.Load()

	port := os.Getenv("PORT")
	if port == "" {
		log.Fatal("PORT not set")
	}
	url := fmt.Sprintf("http://localhost:%s/api/share", port)

	log.Printf("Starting seeder with %d workers, targetting %d entries...", Workers, TotalRequests)
	log.Printf("Target URL: %s", url)

	start := time.Now()
	var wg sync.WaitGroup
	requestsPerWorker := TotalRequests / Workers

	for i := 0; i < Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{
				Timeout: 10 * time.Second,
			}
			for j := 0; j < requestsPerWorker; j++ {
				if sendRequest(client, url) {
					atomic.AddUint64(&successCount, 1)
				} else {
					atomic.AddUint64(&failCount, 1)
				}
			}
		}()
	}

	// Progress reporter
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s := atomic.LoadUint64(&successCount)
				f := atomic.LoadUint64(&failCount)
				elapsed := time.Since(start)
				rate := float64(s) / elapsed.Seconds()
				fmt.Printf("\rProgress: %d/%d (Ok: %d, Fail: %d) | Rate: %.1f req/s | Elapsed: %s",
					s+f, TotalRequests, s, f, rate, elapsed.Round(time.Second))
			case <-done:
				return
			}
		}
	}()

	wg.Wait()
	close(done)
	fmt.Println() // Newline after progress

	elapsed := time.Since(start)
	log.Printf("Seeding complete in %s", elapsed)
	log.Printf("Successful: %d", successCount)
	log.Printf("Failed:     %d", failCount)
}

func sendRequest(client *http.Client, url string) bool {
	payload := map[string]interface{}{
		"text":             randomString(50),
		"expiresInMinutes": rand.Intn(100) + 1,
		"password":         randomString(10),
	}

	jsonPayload, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
