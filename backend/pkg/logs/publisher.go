package logs

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
)

var ctx context.Context
var rdb *redis.Client

func InitPublisher(redisClient *redis.Client) {
	ctx = context.Background()
	rdb = redisClient
}

func PublishLog(event LogEvent) error {
	event.Timestamp = time.Now().Unix()

	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	return rdb.Publish(ctx, "logs", data).Err()
}
