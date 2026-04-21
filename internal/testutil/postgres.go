package testutil

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"vullify/internal/db"
)

// MigrationsDir returns the absolute path to the project migrations folder.
func MigrationsDir(t *testing.T) string {
	t.Helper()
	_, filename, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(filename), "..", "..")
	abs, err := filepath.Abs(filepath.Join(root, "migrations"))
	if err != nil {
		t.Fatalf("migrations path: %v", err)
	}
	return abs
}

// PostgresPool starts PostgreSQL in Docker (testcontainers), runs migrations, and returns a pool.
// Skipped when testing.Short() or when Docker is unavailable.
func PostgresPool(t *testing.T) (*pgxpool.Pool, func()) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping testcontainers (use full test run with Docker)")
	}
	ctx := context.Background()
	ctr, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("vullify"),
		postgres.WithUsername("vullify"),
		postgres.WithPassword("vullify"),
	)
	if err != nil {
		t.Fatalf("postgres container: %v", err)
	}
	connStr, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = ctr.Terminate(ctx)
		t.Fatalf("connection string: %v", err)
	}
	if err := waitPostgresReady(ctx, connStr); err != nil {
		_ = ctr.Terminate(ctx)
		t.Fatalf("postgres not ready: %v", err)
	}
	if err := migrateUp(connStr, MigrationsDir(t)); err != nil {
		_ = ctr.Terminate(ctx)
		t.Fatalf("migrate: %v", err)
	}
	pool, err := db.Connect(ctx, connStr)
	if err != nil {
		_ = ctr.Terminate(ctx)
		t.Fatalf("connect: %v", err)
	}
	cleanup := func() {
		pool.Close()
		_ = ctr.Terminate(context.Background())
	}
	return pool, cleanup
}

func waitPostgresReady(ctx context.Context, dsn string) error {
	const maxAttempts = 60
	for i := 0; i < maxAttempts; i++ {
		c, err := pgx.Connect(ctx, dsn)
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(500 * time.Millisecond):
			}
			continue
		}
		err = c.Ping(ctx)
		_ = c.Close(ctx)
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("postgres not ready after %d attempts", maxAttempts)
}
