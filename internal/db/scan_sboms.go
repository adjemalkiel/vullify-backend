package db

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DeleteScanSBOMsByScan removes SBOM rows for a scan (idempotent retries).
func DeleteScanSBOMsByScan(ctx context.Context, pool *pgxpool.Pool, scanID uuid.UUID) error {
	_, err := pool.Exec(ctx, `DELETE FROM scan_sboms WHERE scan_id = $1`, scanID)
	return err
}

// InsertScanSBOM stores CycloneDX (or SPDX) JSON as JSONB.
func InsertScanSBOM(ctx context.Context, pool *pgxpool.Pool, scanID uuid.UUID, format string, content []byte) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO scan_sboms (scan_id, "format", content, generated_at)
		VALUES ($1, $2::sbom_format, $3::jsonb, now())
	`, scanID, format, content)
	return err
}
