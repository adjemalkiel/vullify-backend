package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// suppressionFilter is a NOT EXISTS subquery that excludes findings matched by an active
// (non-expired) suppression rule.  A rule matches when its cve_id, pkg_name, and image_id
// each either equal the finding's value or are NULL (wildcard).
const suppressionFilter = ` AND NOT EXISTS (
	SELECT 1 FROM suppressions sp
	WHERE (sp.cve_id IS NULL OR sp.cve_id = f.vulnerability_id)
	  AND (sp.pkg_name IS NULL OR sp.pkg_name = f.package_name)
	  AND (sp.image_id IS NULL OR sp.image_id = i.id)
	  AND (sp.expires_at IS NULL OR sp.expires_at > now())
)`

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
		`+suppressionFilter,
	).Scan(&s.TotalFindings); err != nil {
		return s, err
	}
	rows, err := pool.Query(ctx, `
		SELECT f.severity::text, COUNT(*)
		FROM findings f
		JOIN scans s ON s.id = f.scan_id
		JOIN images i ON i.id = s.image_id
		JOIN registries r ON r.id = i.registry_id
		WHERE i.deleted_at IS NULL AND r.deleted_at IS NULL
		`+suppressionFilter+`
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
	Title           string
	LastSeen        *time.Time
}

// GlobalCVERow is a deduplicated CVE view across all findings.
type GlobalCVERow struct {
	VulnerabilityID string
	Severity        string
	Occurrences     int64
	Title           string
	MaxRiskScore    *float64
	LastSeen        *time.Time
}

// ListGlobalCVEs returns deduplicated CVEs across all findings joined with enrichments.
func ListGlobalCVEs(ctx context.Context, pool *pgxpool.Pool, severity, sortBy string, offset, limit int) ([]GlobalCVERow, int, error) {
	baseQ := `
		SELECT f.vulnerability_id, f.severity::text, COUNT(*) AS occurrences,
		       COALESCE(MAX(f.title), '') AS title,
		       COALESCE(MAX(e.risk_score), MAX(f.cvss_v3_score) * 10.0) AS max_risk_score,
		       MAX(f.created_at) AS last_seen
		FROM findings f
		JOIN scans s ON s.id = f.scan_id
		JOIN images i ON i.id = s.image_id
		JOIN registries r ON r.id = i.registry_id
		LEFT JOIN enrichments e ON e.finding_id = f.id
		WHERE i.deleted_at IS NULL AND r.deleted_at IS NULL
		` + suppressionFilter + `
	`
	args := []any{}
	if severity != "" {
		baseQ += fmt.Sprintf(` AND f.severity = $%d::severity`, len(args)+1)
		args = append(args, severity)
	}
	baseQ += ` GROUP BY f.vulnerability_id, f.severity`

	var total int
	countQ := `SELECT COUNT(*) FROM (` + baseQ + `) AS agg`
	if err := pool.QueryRow(ctx, countQ, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	order := "occurrences DESC"
	switch sortBy {
	case "risk_score":
		order = "max_risk_score DESC NULLS LAST, occurrences DESC"
	case "severity":
		order = fmt.Sprintf(`
			CASE severity
				WHEN 'critical' THEN 1
				WHEN 'high' THEN 2
				WHEN 'medium' THEN 3
				WHEN 'low' THEN 4
				ELSE 5
			END, occurrences DESC`)
	}
	baseQ += ` ORDER BY ` + order

	off := len(args) + 1
	listQ := baseQ + fmt.Sprintf(` OFFSET $%d LIMIT $%d`, off, off+1)
	args = append(args, offset, limit)

	rows, err := pool.Query(ctx, listQ, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []GlobalCVERow
	for rows.Next() {
		var r GlobalCVERow
		if err := rows.Scan(&r.VulnerabilityID, &r.Severity, &r.Occurrences, &r.Title, &r.MaxRiskScore, &r.LastSeen); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// ListVulnerabilityReport aggregates findings by vulnerability_id with optional filters.
func ListVulnerabilityReport(ctx context.Context, pool *pgxpool.Pool, severity string, from, to *time.Time, offset, limit int) ([]VulnerabilityReportRow, int, error) {
	q := `
		SELECT f.vulnerability_id, f.severity::text, COUNT(*) AS c, COALESCE(MAX(f.title), '') AS title, MAX(f.created_at) AS last_seen
		FROM findings f
		JOIN scans s ON s.id = f.scan_id
		JOIN images i ON i.id = s.image_id
		JOIN registries r ON r.id = i.registry_id
		WHERE i.deleted_at IS NULL AND r.deleted_at IS NULL
		` + suppressionFilter + `
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
		if err := rows.Scan(&r.VulnerabilityID, &r.Severity, &r.Occurrences, &r.Title, &r.LastSeen); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}
