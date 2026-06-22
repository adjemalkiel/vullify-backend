package scheduler

import (
	"os"
	"time"

	"vullify/internal/scanqueue"
)

// Config holds ticker intervals and related options (loaded from environment).
type Config struct {
	RegistrySyncInterval    time.Duration
	PeriodicRescanInterval  time.Duration
	TargetRescanInterval    time.Duration
	ChangeDetectionInterval time.Duration
	StaleScanAge            time.Duration
	QueueKey                string
}

// LoadConfig reads SCHEDULER_* and SCAN_QUEUE_KEY. Zero duration disables that task.
func LoadConfig() Config {
	c := Config{
		RegistrySyncInterval:    time.Hour,
		PeriodicRescanInterval:  24 * time.Hour,
		TargetRescanInterval:    30 * time.Minute,
		ChangeDetectionInterval: 30 * time.Minute,
		StaleScanAge:            24 * time.Hour,
		QueueKey:                os.Getenv("SCAN_QUEUE_KEY"),
	}
	if v := os.Getenv("SCHEDULER_REGISTRY_SYNC_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.RegistrySyncInterval = d
		}
	}
	if v := os.Getenv("SCHEDULER_PERIODIC_RESCAN_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.PeriodicRescanInterval = d
		}
	}
	if v := os.Getenv("SCHEDULER_CHANGE_DETECTION_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.ChangeDetectionInterval = d
		}
	}
	if v := os.Getenv("SCHEDULER_STALE_SCAN_AGE"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.StaleScanAge = d
		}
	}
	if v := os.Getenv("SCHEDULER_TARGET_RESCAN_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.TargetRescanInterval = d
		}
	}
	return c
}

func queueKey(cfg Config) string {
	if cfg.QueueKey != "" {
		return cfg.QueueKey
	}
	return scanqueue.DefaultKey
}
