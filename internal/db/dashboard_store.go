package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DashboardSummary aggregates high-level counts.
type DashboardSummary struct {
	TotalImages   int64
	TotalScans    int64
	TotalFindings int64
	BySeverity    map[string]int64
}

// GetDashboardSummary returns counts across active registries/images.
func GetDashboardSummary(ctx context.Context, pool *pgxpool.Pool) (DashboardSummary, error) {
	var s DashboardSummary
	s.BySeverity = make(map[string]int64)

	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM images i
		JOIN registries r ON r.id = i.registry_id
		WHERE i.deleted_at IS NULL AND r.deleted_at IS NULL
	`).Scan(&s.TotalImages); err != nil {
		return s, err
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM scans`).Scan(&s.TotalScans); err != nil {
		return s, err
	}
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM findings f
		JOIN scans s ON s.id = f.scan_id
		JOIN images i ON i.id = s.image_id
		JOIN registries r ON r.id = i.registry_id
		WHERE i.deleted_at IS NULL AND r.deleted_at IS NULL
	`).Scan(&s.TotalFindings); err != nil {
		return s, err
	}
	rows, err := pool.Query(ctx, `
		SELECT f.severity::text, COUNT(*)
		FROM findings f
		JOIN scans s ON s.id = f.scan_id
		JOIN images i ON i.id = s.image_id
		JOIN registries r ON r.id = i.registry_id
		WHERE i.deleted_at IS NULL AND r.deleted_at IS NULL
		GROUP BY f.severity
	`)
	if err != nil {
		return s, err
	}
	defer rows.Close()
	for rows.Next() {
		var sev string
		var n int64
		if err := rows.Scan(&sev, &n); err != nil {
			return s, err
		}
		s.BySeverity[sev] = n
	}
	return s, rows.Err()
}

// VulnerabilityReportRow is one CVE aggregate in the report.
type VulnerabilityReportRow struct {
	VulnerabilityID string
	Severity        string
	Occurrences     int64
	LastSeen        *time.Time
}

// ListVulnerabilityReport aggregates findings by vulnerability_id with optional filters.
func ListVulnerabilityReport(ctx context.Context, pool *pgxpool.Pool, severity string, from, to *time.Time, offset, limit int) ([]VulnerabilityReportRow, int, error) {
	q := `
		SELECT f.vulnerability_id, f.severity::text, COUNT(*) AS c, MAX(f.created_at) AS last_seen
		FROM findings f
		JOIN scans s ON s.id = f.scan_id
		JOIN images i ON i.id = s.image_id
		JOIN registries r ON r.id = i.registry_id
		WHERE i.deleted_at IS NULL AND r.deleted_at IS NULL
	`
	args := []any{}
	if severity != "" {
		q += fmt.Sprintf(` AND f.severity = $%d::severity`, len(args)+1)
		args = append(args, severity)
	}
	if from != nil {
		q += fmt.Sprintf(` AND f.created_at >= $%d`, len(args)+1)
		args = append(args, *from)
	}
	if to != nil {
		q += fmt.Sprintf(` AND f.created_at < $%d`, len(args)+1)
		args = append(args, *to)
	}
	q += ` GROUP BY f.vulnerability_id, f.severity`

	var total int
	countQ := `SELECT COUNT(*) FROM (` + q + `) AS agg`
	if err := pool.QueryRow(ctx, countQ, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	off := len(args) + 1
	listQ := q + fmt.Sprintf(` ORDER BY c DESC OFFSET $%d LIMIT $%d`, off, off+1)
	args = append(args, offset, limit)

	rows, err := pool.Query(ctx, listQ, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []VulnerabilityReportRow
	for rows.Next() {
		var r VulnerabilityReportRow
		if err := rows.Scan(&r.VulnerabilityID, &r.Severity, &r.Occurrences, &r.LastSeen); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}
