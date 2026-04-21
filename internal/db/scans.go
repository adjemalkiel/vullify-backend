package db

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// UpdateScanRunning sets status to running and started_at (first time only).
func UpdateScanRunning(ctx context.Context, pool *pgxpool.Pool, scanID uuid.UUID) error {
	tag, err := pool.Exec(ctx, `
		UPDATE scans
		SET status = 'running',
		    started_at = COALESCE(started_at, now())
		WHERE id = $1
	`, scanID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("scan not found: %s", scanID)
	}
	return nil
}

// UpdateScanCompleted sets status completed, completed_at, and optional trivy version.
func UpdateScanCompleted(ctx context.Context, pool *pgxpool.Pool, scanID uuid.UUID, trivyVersion string) error {
	_, err := pool.Exec(ctx, `
		UPDATE scans
		SET status = 'completed',
		    completed_at = now(),
		    error_message = NULL,
		    trivy_version = NULLIF($2, '')
		WHERE id = $1
	`, scanID, trivyVersion)
	return err
}

// UpdateScanFailed sets status failed, completed_at, and error_message.
func UpdateScanFailed(ctx context.Context, pool *pgxpool.Pool, scanID uuid.UUID, errMsg string) error {
	_, err := pool.Exec(ctx, `
		UPDATE scans
		SET status = 'failed',
		    completed_at = now(),
		    error_message = $2
		WHERE id = $1
	`, scanID, errMsg)
	return err
}
