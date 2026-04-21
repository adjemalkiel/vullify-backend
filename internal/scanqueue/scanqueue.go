package scanqueue

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// DefaultKey is the Redis list name for LPUSH/BRPOP scan jobs (must match worker).
const DefaultKey = "vullify:scan:queue"

// Enqueue pushes a worker-compatible job (LPUSH for BRPOP consumer).
func Enqueue(ctx context.Context, rdb *redis.Client, queueKey string, scanID uuid.UUID, imageRef string) error {
	if queueKey == "" {
		queueKey = DefaultKey
	}
	payload, err := json.Marshal(struct {
		ScanID   uuid.UUID `json:"scan_id"`
		ImageRef string    `json:"image_ref"`
	}{ScanID: scanID, ImageRef: imageRef})
	if err != nil {
		return err
	}
	return rdb.LPush(ctx, queueKey, payload).Err()
}
