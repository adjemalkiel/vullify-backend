package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"vullify/internal/db"
	"vullify/internal/enrichment"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://vullify:vullify@localhost:5432/vullify?sslmode=disable"
	}
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}

	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		slog.Error("db connect", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	rdb, err := db.NewRedisClient(redisAddr)
	if err != nil {
		slog.Error("redis parse", "err", err)
		os.Exit(1)
	}
	defer func() { _ = rdb.Close() }()
	if err := rdb.Ping(ctx).Err(); err != nil {
		slog.Error("redis ping", "err", err)
		os.Exit(1)
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	repo := db.NewRepository(pool)
	enr := enrichment.NewEnricher(repo, rdb, log)
	if ch := os.Getenv("SCAN_EVENTS_CHANNEL"); ch != "" {
		enr.EventsChannel = ch
	}
	if key := os.Getenv("KEV_REDIS_KEY"); key != "" {
		enr.KEVRedisKey = key
	}

	if err := enr.Start(ctx); err != nil {
		slog.Error("enricher stopped", "err", err)
		os.Exit(1)
	}
}
