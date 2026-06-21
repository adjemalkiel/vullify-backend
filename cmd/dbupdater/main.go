package main

import (
	"context"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func main() {
	trivyPath := getenv("TRIVY_PATH", "trivy")
	cacheDir := getenv("TRIVY_CACHE_DIR", "/var/trivy/cache")
	interval := getenvDuration("DB_UPDATE_INTERVAL", 6*time.Hour)

	log.Printf("dbupdater starting: trivy=%s cache=%s interval=%s", trivyPath, cacheDir, interval)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := runUpdate(ctx, trivyPath, cacheDir); err != nil {
		log.Printf("initial db download failed: %v (will retry)", err)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("dbupdater: shutting down")
			return
		case <-ticker.C:
			if err := runUpdate(ctx, trivyPath, cacheDir); err != nil {
				slog.Error("db update failed", "err", err)
			}
		}
	}
}

func runUpdate(ctx context.Context, trivyPath, cacheDir string) error {
	log.Println("dbupdater: downloading trivy database...")
	cmd := exec.CommandContext(ctx, trivyPath,
		"image",
		"--download-db-only",
		"--db-repository", "ghcr.io/aquasecurity/trivy-db",
	)
	cmd.Env = append(os.Environ(), "TRIVY_CACHE_DIR="+cacheDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	start := time.Now()
	if err := cmd.Run(); err != nil {
		return err
	}
	log.Printf("dbupdater: database updated in %s", time.Since(start).Round(time.Second))
	return nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := strconv.Atoi(v); err == nil && d > 0 {
			return time.Duration(d) * time.Second
		}
	}
	return def
}
