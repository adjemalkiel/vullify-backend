package db

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ScanCompletionParams holds optional metadata fields for scan completion.
type ScanCompletionParams struct {
	TrivyVersion  string
	DurationMS    *int
	ImageOS       string
	ImageArch     string
	ImageSize     *int64
	LayerCount    *int
	BaseImage     string
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
	UnknownCount  int
}

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

// UpdateScanCompleted sets status completed, completed_at, and optional metadata.
func UpdateScanCompleted(ctx context.Context, pool *pgxpool.Pool, scanID uuid.UUID, params ScanCompletionParams) error {
	_, err := pool.Exec(ctx, `
		UPDATE scans
		SET status = 'completed',
		    completed_at = now(),
		    error_message = NULL,
		    trivy_version = NULLIF($2, ''),
		    critical_count = $3,
		    high_count = $4,
		    medium_count = $5,
		    low_count = $6,
		    unknown_count = $7,
		    duration_ms = $8,
		    image_os = NULLIF($9, ''),
		    image_arch = NULLIF($10, ''),
		    image_size = $11,
		    layer_count = $12,
		    base_image = NULLIF($13, '')
		WHERE id = $1
	`,
		scanID,
		params.TrivyVersion,
		params.CriticalCount,
		params.HighCount,
		params.MediumCount,
		params.LowCount,
		params.UnknownCount,
		params.DurationMS,
		params.ImageOS,
		params.ImageArch,
		params.ImageSize,
		params.LayerCount,
		params.BaseImage,
	)
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

// CancelScan sets status to cancelled for pending or running scans.
func CancelScan(ctx context.Context, pool *pgxpool.Pool, scanID uuid.UUID) error {
	tag, err := pool.Exec(ctx, `
		UPDATE scans
		SET status = 'cancelled',
		    completed_at = now()
		WHERE id = $1 AND status IN ('pending', 'running')
	`, scanID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("scan not found or not cancellable: %s", scanID)
	}
	return nil
}
