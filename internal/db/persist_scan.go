package db

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PersistScanResults replaces findings and SBOM for a scan and marks it completed in one transaction.
func PersistScanResults(ctx context.Context, pool *pgxpool.Pool, scanID uuid.UUID, rows []FindingRow, sbom []byte, trivyVersion string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `DELETE FROM findings WHERE scan_id = $1`, scanID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM scan_sboms WHERE scan_id = $1`, scanID); err != nil {
		return err
	}

	batch := &pgx.Batch{}
	for _, r := range rows {
		sev := normalizeSeverity(r.Severity)
		vid := r.VulnerabilityID
		if vid == "" {
			vid = "UNKNOWN"
		}
		pkg := r.PackageName
		if pkg == "" {
			pkg = "unknown"
		}
		batch.Queue(`
			INSERT INTO findings (
				scan_id, vulnerability_id, package_name, installed_version, fixed_version,
				severity, title, description, data_source
			) VALUES (
				$1, $2, $3, $4, $5,
				$6::severity, $7, $8, $9
			)`,
			scanID, vid, pkg, nullIfEmpty(r.InstalledVersion), nullIfEmpty(r.FixedVersion),
			sev, nullIfEmpty(r.Title), nullIfEmpty(r.Description), nullIfEmpty(r.DataSource),
		)
	}
	if batch.Len() > 0 {
		br := tx.SendBatch(ctx, batch)
		for i := 0; i < batch.Len(); i++ {
			if _, err := br.Exec(); err != nil {
				br.Close()
				return fmt.Errorf("finding row %d: %w", i, err)
			}
		}
		if err := br.Close(); err != nil {
			return err
		}
	}

	if len(sbom) > 0 {
		if _, err := tx.Exec(ctx, `
			INSERT INTO scan_sboms (scan_id, "format", content, generated_at)
			VALUES ($1, 'cyclonedx'::sbom_format, $2::jsonb, now())
		`, scanID, sbom); err != nil {
			return err
		}
	}

	if _, err := tx.Exec(ctx, `
		UPDATE scans
		SET status = 'completed',
		    completed_at = now(),
		    error_message = NULL,
		    trivy_version = NULLIF($2, '')
		WHERE id = $1
	`, scanID, trivyVersion); err != nil {
		return err
	}

	return tx.Commit(ctx)
}
