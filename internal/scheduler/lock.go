package scheduler

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

const lockKeyPrefix = "vullify:scheduler:lock:"

// tryLock acquires a distributed lock with SET NX EX. Returns false if another holder has the lock.
func tryLock(ctx context.Context, rdb *redis.Client, name string, ttl time.Duration) (bool, error) {
	if ttl < time.Second {
		ttl = time.Second
	}
	return rdb.SetNX(ctx, lockKeyPrefix+name, "1", ttl).Result()
}

// lockTTLForInterval is slightly shorter than the tick interval so the lock expires if a run stalls.
func lockTTLForInterval(interval time.Duration) time.Duration {
	if interval <= 0 {
		return time.Minute
	}
	ttl := interval * 9 / 10
	if ttl < 2*time.Second {
		return 2 * time.Second
	}
	return ttl
}
