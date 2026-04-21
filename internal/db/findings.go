package db

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// FindingRow is a row to insert into findings.
type FindingRow struct {
	VulnerabilityID  string
	PackageName      string
	InstalledVersion string
	FixedVersion     string
	Severity         string // critical|high|medium|low|unknown
	Title            string
	Description      string
	DataSource       string
}

// DeleteFindingsByScan removes findings for a scan (idempotent retries).
func DeleteFindingsByScan(ctx context.Context, pool *pgxpool.Pool, scanID uuid.UUID) error {
	_, err := pool.Exec(ctx, `DELETE FROM findings WHERE scan_id = $1`, scanID)
	return err
}

// BatchInsertFindings inserts findings for a scan in one batch.
func BatchInsertFindings(ctx context.Context, pool *pgxpool.Pool, scanID uuid.UUID, rows []FindingRow) error {
	if len(rows) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, r := range rows {
		sev := normalizeSeverity(r.Severity)
		batch.Queue(`
			INSERT INTO findings (
				scan_id, vulnerability_id, package_name, installed_version, fixed_version,
				severity, title, description, data_source
			) VALUES (
				$1, $2, $3, $4, $5,
				$6::severity, $7, $8, $9
			)`,
			scanID, r.VulnerabilityID, r.PackageName, nullIfEmpty(r.InstalledVersion), nullIfEmpty(r.FixedVersion),
			sev, nullIfEmpty(r.Title), nullIfEmpty(r.Description), nullIfEmpty(r.DataSource),
		)
	}
	br := pool.SendBatch(ctx, batch)
	defer br.Close()
	for i := 0; i < batch.Len(); i++ {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("finding row %d: %w", i, err)
		}
	}
	return nil
}

func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "high", "medium", "low", "unknown":
		return strings.ToLower(strings.TrimSpace(s))
	default:
		return "unknown"
	}
}

func nullIfEmpty(s string) interface{} {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}
