package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"vullify/internal/api"
	"vullify/internal/db"
	"vullify/internal/scheduler"
)

func main() {
	addr := getenv("HTTP_ADDR", ":8080")
	dsn := getenv("DATABASE_URL", "postgres://vullify:vullify@localhost:5432/vullify?sslmode=disable")
	redisAddr := getenv("REDIS_ADDR", "localhost:6379")

	ctx := context.Background()

	migrationsDir := getenv("MIGRATIONS_DIR", "migrations")
	if err := db.Migrate(dsn, migrationsDir); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer pool.Close()

	rdb := redis.NewClient(&redis.Options{Addr: redisAddr})
	defer func() { _ = rdb.Close() }()
	if err := rdb.Ping(ctx).Err(); err != nil {
		slog.Warn("redis ping failed; scan enqueue will fail until Redis is up", "err", err)
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           api.NewHandler(pool, rdb),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Printf("api listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		scheduler.Run(sigCtx, pool, rdb, slog.Default())
	}()

	<-sigCtx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}
	wg.Wait()
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
