package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

func main() {
	baseURL := "http://localhost:3000/api"

	// 1. Create a secret that expires in 1 minute
	payload := map[string]interface{}{
		"text":             "This will self-destruct in 60 seconds",
		"expiresInMinutes": 1,
	}
	jsonData, _ := json.Marshal(payload)

	resp, err := http.Post(baseURL+"/share", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Error creating secret: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Failed to create secret, status: %d\n", resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		fmt.Println(string(body))
		return
	}

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	secretID := result["id"]
	fmt.Printf("Created secret with ID: %s\n", secretID)

	// 2. Wait for expiration (slightly more than 5 seconds to be safe)
	fmt.Println("Waiting for 10 seconds for cleanup...")
	time.Sleep(10 * time.Second)

	// 3. Try to view the secret (should fail with 404)
	respView, err := http.Get(baseURL + "/view/" + secretID)
	if err != nil {
		fmt.Printf("Error viewing secret: %v\n", err)
		return
	}
	defer respView.Body.Close()

	if respView.StatusCode == http.StatusNotFound {
		fmt.Println("SUCCESS: Secret was deleted after expiration (404 Not Found).")
	} else if respView.StatusCode == http.StatusOK {
		fmt.Println("FAILURE: Secret still exists!")
	} else {
		fmt.Printf("Unexpected status code: %d\n", respView.StatusCode)
	}
}
