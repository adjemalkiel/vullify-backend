package scheduler

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// Run starts ticker loops for enabled tasks. Blocks until ctx is cancelled, then waits for goroutines.
func Run(ctx context.Context, pool *pgxpool.Pool, rdb *redis.Client, log *slog.Logger) {
	cfg := LoadConfig()
	if log == nil {
		log = slog.Default()
	}

	var wg sync.WaitGroup

	if cfg.RegistrySyncInterval > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runTicker(ctx, cfg.RegistrySyncInterval, "registry_sync", log, rdb, func(inner context.Context) {
				runRegistrySync(inner, pool, log)
			})
		}()
	}

	if cfg.PeriodicRescanInterval > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runTicker(ctx, cfg.PeriodicRescanInterval, "periodic_rescan", log, rdb, func(inner context.Context) {
				runPeriodicRescan(inner, pool, rdb, cfg, log)
			})
		}()
	}

	if cfg.ChangeDetectionInterval > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runTicker(ctx, cfg.ChangeDetectionInterval, "change_detection", log, rdb, func(inner context.Context) {
				runChangeDetection(inner, pool, rdb, cfg, log)
			})
		}()
	}

	if cfg.TargetRescanInterval > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runTicker(ctx, cfg.TargetRescanInterval, "target_rescan", log, rdb, func(inner context.Context) {
				runTargetRescan(inner, pool, rdb, cfg, log)
			})
		}()
	}

	<-ctx.Done()
	wg.Wait()
}

func runTicker(ctx context.Context, interval time.Duration, name string, log *slog.Logger, rdb *redis.Client, fn func(context.Context)) {
	lockTTL := lockTTLForInterval(interval)
	jobTO := jobTimeoutFor(interval)

	runJob := func() {
		jobCtx, cancel := context.WithTimeout(ctx, jobTO)
		defer cancel()

		ok, err := tryLock(jobCtx, rdb, name, lockTTL)
		if err != nil {
			log.Warn("scheduler lock failed", "task", name, "err", err)
			return
		}
		if !ok {
			log.Debug("scheduler skipped (lock held)", "task", name)
			return
		}

		start := time.Now()
		log.Info("scheduler task start", "task", name)
		fn(jobCtx)
		log.Info("scheduler task end", "task", name, "duration", time.Since(start).String())
	}

	runJob()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runJob()
		}
	}
}
