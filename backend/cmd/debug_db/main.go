package main

import (
	"log"

	"github.com/Pestip108/Project-Simulation/backend/pkg/secret"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func main() {
	db, err := gorm.Open(sqlite.Open("secrets.db"), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	var secrets []secret.Secret
	db.Find(&secrets)

	log.Printf("Found %d secrets", len(secrets))
	for i, s := range secrets {
		if i >= 5 { break } // just show first 5
		log.Printf("ID: %d, ExpiresAt: %v, DeletedAt: %v", s.ID, s.ExpiresAt, s.DeletedAt)
	}
    
    // Check raw string values for DeletedAt
    var raw []map[string]interface{}
    db.Raw("SELECT id, deleted_at FROM secrets LIMIT 5").Scan(&raw)
    log.Println("Raw values:", raw)
}
