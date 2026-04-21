package db

import (
	"context"

	goredis "github.com/redis/go-redis/v9"
)

// NewRedisClient returns a Redis client for the given address (e.g. localhost:6379).
func NewRedisClient(addr string) *goredis.Client {
	return goredis.NewClient(&goredis.Options{Addr: addr})
}

// PingRedis verifies Redis connectivity.
func PingRedis(ctx context.Context, c *goredis.Client) error {
	return c.Ping(ctx).Err()
}
