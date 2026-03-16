package log_listener

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Pestip108/Project-Simulation/backend/pkg/logs"
	"github.com/Pestip108/Project-Simulation/backend/pkg/models"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

var ctxSub context.Context

func RunLogSubscriber(rdb *redis.Client, db *gorm.DB) {
	ctxSub = context.Background()

	sub := rdb.Subscribe(ctxSub, "logs")
	ch := sub.Channel()

	fmt.Println("Logger service started")

	for msg := range ch {

		var event logs.LogEvent
		if err := json.Unmarshal([]byte(msg.Payload), &event); err != nil {
			fmt.Println("Invalid log event:", err)
			continue
		}

		logEntry := models.Log{
			Action:    event.Action,
			Timestamp: event.Timestamp,
		}

		if err := db.Create(&logEntry).Error; err != nil {
			fmt.Println("Failed to store log:", err)
		}

		fmt.Printf("Stored log: %+v\n", logEntry)
	}
}
