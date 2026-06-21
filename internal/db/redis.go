package db

import (
	"context"
	"strings"

	goredis "github.com/redis/go-redis/v9"
)

// NewRedisClient returns a Redis client for the given address.
// The address may be a plain host:port (e.g. "localhost:6379") or a full
// redis:// URL (e.g. "redis://user:pass@host:6379").
func NewRedisClient(addr string) (*goredis.Client, error) {
	if strings.HasPrefix(addr, "redis://") || strings.HasPrefix(addr, "rediss://") {
		opts, err := goredis.ParseURL(addr)
		if err != nil {
			return nil, err
		}
		return goredis.NewClient(opts), nil
	}
	return goredis.NewClient(&goredis.Options{Addr: addr}), nil
}

// PingRedis verifies Redis connectivity.
func PingRedis(ctx context.Context, c *goredis.Client) error {
	return c.Ping(ctx).Err()
}
