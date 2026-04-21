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

	QueueKey      string // Redis list for LPUSH/BRPOP
	EventsChannel string // Pub/Sub channel for scan.completed

	PoolSize   int // concurrent BRPOP workers; default 3
	MaxRetries int // per job; default 3

	TrivyPath string // default "trivy"; used for version probe

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

	if err := db.UpdateScanRunning(ctx, r.Pool, scanID); err != nil {
		_ = r.publishScanEvent(ctx, scanID, "failed", err.Error())
		_ = db.UpdateScanFailed(ctx, r.Pool, scanID, err.Error())
		return err
	}

	res, err := r.Scanner.ScanImage(ctx, job.ImageRef)
	if err != nil {
		msg := err.Error()
		_ = db.UpdateScanFailed(ctx, r.Pool, scanID, msg)
		_ = r.publishScanEvent(ctx, scanID, "failed", msg)
		return err
	}

	rows := vulnResultsToRows(res.Vulnerabilities)
	if err := db.PersistScanResults(ctx, r.Pool, scanID, rows, res.SBOM, trivyVer); err != nil {
		msg := err.Error()
		_ = db.UpdateScanFailed(ctx, r.Pool, scanID, msg)
		_ = r.publishScanEvent(ctx, scanID, "failed", msg)
		return err
	}

	if err := r.publishScanEvent(ctx, scanID, "completed", ""); err != nil {
		log.Warn("publish scan.completed", "scan_id", scanID, "err", err)
	}
	log.Info("scan completed", "scan_id", scanID)
	return nil
}

func vulnResultsToRows(vs []scanner.VulnResult) []db.FindingRow {
	out := make([]db.FindingRow, 0, len(vs))
	for _, v := range vs {
		vid := v.VulnerabilityID
		if strings.TrimSpace(vid) == "" {
			vid = "UNKNOWN"
		}
		pkg := v.PackageName
		if strings.TrimSpace(pkg) == "" {
			pkg = "unknown"
		}
		out = append(out, db.FindingRow{
			VulnerabilityID:  vid,
			PackageName:      pkg,
			InstalledVersion: v.InstalledVersion,
			FixedVersion:     v.FixedVersion,
			Severity:         v.Severity,
			Title:            v.Title,
			Description:      v.Description,
			DataSource:       v.DataSource,
		})
	}
	return out
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
