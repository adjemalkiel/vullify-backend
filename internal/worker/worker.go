package worker

import (
	"context"
	"log/slog"
	"os"
	"strconv"

	"vullify/internal/db"
	"vullify/internal/scanner"
)

// Run loads configuration from the environment, connects to Postgres and Redis,
// and runs the scan worker pool until SIGINT/SIGTERM cancels the context.
func Run(ctx context.Context) error {
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
		return err
	}
	defer pool.Close()

	rdb, err := db.NewRedisClient(redisAddr)
	if err != nil {
		return err
	}
	defer func() { _ = rdb.Close() }()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return err
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	trivyPath := os.Getenv("TRIVY_PATH")
	if trivyPath == "" {
		trivyPath = "trivy"
	}
	sc := &scanner.TrivyScanner{TrivyPath: trivyPath}

	runner := &Runner{
		Pool:          pool,
		Redis:         rdb,
		Scanner:       sc,
		QueueKey:      os.Getenv("SCAN_QUEUE_KEY"),
		EventsChannel: os.Getenv("SCAN_EVENTS_CHANNEL"),
		PoolSize:      envInt("WORKER_POOL_SIZE", 2),
		MaxRetries:    envInt("JOB_MAX_RETRIES", 3),
		TrivyPath:     trivyPath,
		Log:           log,
	}

	return runner.StartWorker(ctx)
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
