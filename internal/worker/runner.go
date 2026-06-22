package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"vullify/internal/db"
	"vullify/internal/scanner"
)

// Runner wires Redis queue, Postgres, and Trivy scanning.
type Runner struct {
	Pool    *pgxpool.Pool
	Redis   *redis.Client
	Scanner scanner.Scanner

	QueueKey      string
	EventsChannel string

	PoolSize   int
	MaxRetries int

	TrivyPath string

	Log *slog.Logger
}

// EnqueueScan serializes a job and pushes it onto the Redis list (LPUSH; FIFO with BRPOP).
func (r *Runner) EnqueueScan(ctx context.Context, scanID uuid.UUID, imageRef string) error {
	r.initDefaults()
	if strings.TrimSpace(imageRef) == "" {
		return fmt.Errorf("worker: empty image_ref")
	}
	key := r.queueKey()
	payload, err := encodeJob(ScanJob{ScanID: scanID, ImageRef: strings.TrimSpace(imageRef)})
	if err != nil {
		return err
	}
	return r.Redis.LPush(ctx, key, payload).Err()
}

// StartWorker runs a pool of consumers until ctx is cancelled, then waits for workers to exit.
func (r *Runner) StartWorker(ctx context.Context) error {
	r.initDefaults()
	log := r.Log

	var wg sync.WaitGroup
	for i := 0; i < r.PoolSize; i++ {
		wg.Add(1)
		id := i
		go func() {
			defer wg.Done()
			r.workerLoop(ctx, id)
		}()
	}

	log.Info("scan workers started", "pool_size", r.PoolSize, "queue", r.queueKey(), "events", r.eventsChannel())
	<-ctx.Done()
	log.Info("scan workers shutting down")
	wg.Wait()
	log.Info("scan workers stopped")
	if err := ctx.Err(); errors.Is(err, context.Canceled) {
		return nil
	}
	return ctx.Err()
}

func (r *Runner) workerLoop(ctx context.Context, workerID int) {
	log := r.Log
	key := r.queueKey()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		res, err := r.Redis.BRPop(ctx, 0, key).Result()
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, redis.ErrClosed) {
				return
			}
			log.Error("brpop failed", "worker", workerID, "err", err)
			continue
		}
		if len(res) != 2 {
			continue
		}
		payload := res[1]
		job, err := decodeJob([]byte(payload))
		if err != nil {
			log.Error("decode job", "worker", workerID, "err", err)
			continue
		}

		log.Info("job received", "worker", workerID, "scan_id", job.ScanID, "image_ref", job.ImageRef)

		if err := r.processJobWithRetry(ctx, job); err != nil {
			log.Error("job failed after retries", "worker", workerID, "scan_id", job.ScanID, "err", err)
		}
	}
}

func (r *Runner) processJobWithRetry(ctx context.Context, job ScanJob) error {
	log := r.Log
	var lastErr error
	for attempt := 0; attempt < r.MaxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(100*(1<<uint(attempt-1))) * time.Millisecond
			log.Info("retrying job", "scan_id", job.ScanID, "attempt", attempt+1, "backoff", backoff)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}
		lastErr = r.runPipeline(ctx, job)
		if lastErr == nil {
			return nil
		}
		log.Warn("job attempt failed", "scan_id", job.ScanID, "attempt", attempt+1, "err", lastErr)
	}
	return lastErr
}

func (r *Runner) runPipeline(ctx context.Context, job ScanJob) error {
	log := r.Log
	scanID := job.ScanID
	trivyVer := r.probeTrivyVersion(ctx)

	r.setScanPhase(ctx, scanID, "initializing")

	if err := db.UpdateScanRunning(ctx, r.Pool, scanID); err != nil {
		_ = r.setScanPhase(ctx, scanID, "failed")
		_ = r.publishScanEvent(ctx, scanID, "failed", err.Error())
		_ = db.UpdateScanFailed(ctx, r.Pool, scanID, err.Error())
		return err
	}

	r.setScanPhase(ctx, scanID, "scanning")
	res, err := r.Scanner.ScanImage(ctx, job.ImageRef, scanOptsFromJob(job))
	if err != nil {
		msg := err.Error()
		_ = r.setScanPhase(ctx, scanID, "failed")
		_ = db.UpdateScanFailed(ctx, r.Pool, scanID, msg)
		_ = r.publishScanEvent(ctx, scanID, "failed", msg)
		return err
	}

	r.setScanPhase(ctx, scanID, "persisting")
	if err := db.PersistScanResults(ctx, r.Pool, scanID, res, trivyVer); err != nil {
		msg := err.Error()
		_ = r.setScanPhase(ctx, scanID, "failed")
		_ = db.UpdateScanFailed(ctx, r.Pool, scanID, msg)
		_ = r.publishScanEvent(ctx, scanID, "failed", msg)
		return err
	}

	r.setScanPhase(ctx, scanID, "completed")
	if err := r.publishScanEvent(ctx, scanID, "completed", ""); err != nil {
		log.Warn("publish scan.completed", "scan_id", scanID, "err", err)
	}
	log.Info("scan completed", "scan_id", scanID)
	return nil
}

type scanEvent struct {
	Event  string `json:"event"`
	ScanID string `json:"scan_id"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

func (r *Runner) publishScanEvent(ctx context.Context, scanID uuid.UUID, status, errMsg string) error {
	payload, err := json.Marshal(scanEvent{
		Event:  "scan.completed",
		ScanID: scanID.String(),
		Status: status,
		Error:  errMsg,
	})
	if err != nil {
		return err
	}
	return r.Redis.Publish(ctx, r.eventsChannel(), payload).Err()
}

// setScanPhase stores the current pipeline phase in Redis with a 30-minute TTL.
// Phases: initializing, scanning, persisting, completed, failed.
func (r *Runner) setScanPhase(ctx context.Context, scanID uuid.UUID, phase string) error {
	return r.Redis.SetEx(ctx,
		fmt.Sprintf("vullify:scan:%s:phase", scanID.String()),
		phase,
		30*time.Minute,
	).Err()
}

func (r *Runner) probeTrivyVersion(ctx context.Context) string {
	if v := os.Getenv("TRIVY_VERSION"); v != "" {
		return v
	}
	path := r.TrivyPath
	if path == "" {
		path = "trivy"
	}
	cmd := exec.CommandContext(ctx, path, "version", "--format", "json")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	var meta struct {
		Version string `json:"Version"`
	}
	if err := json.Unmarshal(out, &meta); err != nil {
		return ""
	}
	return meta.Version
}

func (r *Runner) initDefaults() {
	if r.QueueKey == "" {
		r.QueueKey = "vullify:scan:queue"
	}
	if r.EventsChannel == "" {
		r.EventsChannel = "vullify:scan:events"
	}
	if r.PoolSize <= 0 {
		r.PoolSize = 3
	}
	if r.MaxRetries <= 0 {
		r.MaxRetries = 3
	}
	if r.Log == nil {
		r.Log = slog.Default()
	}
}

func scanOptsFromJob(job ScanJob) *scanner.ScanImageOpts {
	opts := &scanner.ScanImageOpts{
		CacheDir: os.TempDir() + "/trivy-cache/" + job.ScanID.String(),
	}
	if job.RegCreds != nil {
		opts.RegistryUsername = job.RegCreds.Username
		opts.RegistryPassword = job.RegCreds.Password
	}
	return opts
}

func (r *Runner) queueKey() string {
	if r.QueueKey != "" {
		return r.QueueKey
	}
	return "vullify:scan:queue"
}

func (r *Runner) eventsChannel() string {
	if r.EventsChannel != "" {
		return r.EventsChannel
	}
	return "vullify:scan:events"
}
