package testutil

import (
	"context"
	"fmt"
	"testing"

	"github.com/redis/go-redis/v9"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

// RedisClient starts Redis in Docker and returns a go-redis client.
// Skipped when testing.Short().
func RedisClient(t *testing.T) (*redis.Client, func()) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping testcontainers redis")
	}
	ctx := context.Background()
	ctr, err := tcredis.Run(ctx, "redis:7-alpine")
	if err != nil {
		t.Fatalf("redis container: %v", err)
	}
	host, err := ctr.Host(ctx)
	if err != nil {
		_ = ctr.Terminate(ctx)
		t.Fatalf("redis host: %v", err)
	}
	mapped, err := ctr.MappedPort(ctx, "6379/tcp")
	if err != nil {
		_ = ctr.Terminate(ctx)
		t.Fatalf("redis port: %v", err)
	}
	addr := fmt.Sprintf("%s:%s", host, mapped.Port())
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		_ = ctr.Terminate(ctx)
		t.Fatalf("redis ping: %v", err)
	}
	cleanup := func() {
		_ = rdb.Close()
		_ = ctr.Terminate(context.Background())
	}
	return rdb, cleanup
}
