package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/joho/godotenv"
)

type MemStats struct {
	Alloc        uint64  `json:"Alloc"`
	TotalAlloc   uint64  `json:"TotalAlloc"`
	Sys          uint64  `json:"Sys"`
	NumGC        uint32  `json:"NumGC"`
	TimeDiffAvg  float64 `json:"TimeDiffAvg"`
	DeletedCount int64   `json:"DeletedCount"`
}

func main() {
	// Try to load .env from backend folder if present
	godotenv.Load()

	port := os.Getenv("PORT")
	if port == "" {
		log.Fatal("PORT not set")
	}

	url := fmt.Sprintf("http://localhost:%s/api/metrics", port)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	clearScreen()

	for range ticker.C {
		stats, err := fetchMetrics(url)
		if err != nil {
			log.Printf("Error fetching metrics: %v", err)
			continue
		}

		printStats(stats)
	}
}

func fetchMetrics(url string) (*MemStats, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var stats MemStats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, err
	}

	return &stats, nil
}

func printStats(stats *MemStats) {
	// Move cursor to top-left
	fmt.Print("\033[H")

	fmt.Println("=== Memory Monitor ===")
	fmt.Printf("Allocated:      %s      \n", formatBytes(stats.Alloc))
	fmt.Printf("Total Alloc:    %s      \n", formatBytes(stats.TotalAlloc))
	fmt.Printf("System Memory:  %s      \n", formatBytes(stats.Sys))
	fmt.Printf("Num GC:         %d      \n", stats.NumGC)
	fmt.Printf("Avg Time Diff:  %.4fs   \n", stats.TimeDiffAvg)
	fmt.Printf("Deleted Count:  %d      \n", stats.DeletedCount)
	fmt.Println("======================")
	fmt.Println("Press Ctrl+C to exit")
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func clearScreen() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	} else {
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
}
