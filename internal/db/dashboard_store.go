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
func ListGlobalCVEs(ctx context.Context, pool *pgxpool.Pool, severity, sortBy string, hasFix, isKEV *bool, offset, limit int) ([]GlobalCVERow, int, error) {
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

	// Build HAVING clauses for optional boolean filters.
	var havings []string
	if hasFix != nil {
		val := 0
		if *hasFix {
			val = 1
		}
		havings = append(havings, fmt.Sprintf(`MAX(CASE WHEN f.fixed_version IS NOT NULL AND f.fixed_version != '' THEN 1 ELSE 0 END) = $%d`, len(args)+1))
		args = append(args, val)
	}
	if isKEV != nil {
		havings = append(havings, fmt.Sprintf(`BOOL_OR(COALESCE(e.kev_listed, false)) = $%d`, len(args)+1))
		args = append(args, *isKEV)
	}
	if len(havings) > 0 {
		baseQ += ` HAVING ` + havings[0]
		for i := 1; i < len(havings); i++ {
			baseQ += ` AND ` + havings[i]
		}
	}

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

// CVEDetail is the aggregate view of a single CVE across all findings.
type CVEDetail struct {
	VulnerabilityID string
	Title           string
	Description     string
	Severity        string
	Occurrences     int64
	RiskScore       *float64
	CVSSV3Score     *float64
	EPSSScore       *float64
	EPSSPercentile  *float64
	KEVListed       bool
	KEVDateAdded    *time.Time
	ExploitExists   bool
	DataSources     []string
	AffectedImages  []CVEImageSummary
	LastSeen        *time.Time
}

// CVEImageSummary is a single image affected by a CVE.
type CVEImageSummary struct {
	ImageID    string `json:"image_id"`
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	FixedVer   string `json:"fixed_version,omitempty"`
}

// GetCVEDetail returns aggregated information about a single CVE.
func GetCVEDetail(ctx context.Context, pool *pgxpool.Pool, cveID string) (CVEDetail, error) {
	var d CVEDetail
	err := pool.QueryRow(ctx, `
		SELECT
			f.vulnerability_id,
			COALESCE(MAX(f.title), '') AS title,
			COALESCE(MAX(f.description), '') AS description,
			MAX(f.severity::text) AS severity,
			COUNT(*) AS occurrences,
			MAX(e.risk_score) AS max_risk_score,
			MAX(f.cvss_v3_score) AS max_cvss_v3,
			MAX(e.epss_score) AS max_epss,
			MAX(e.epss_percentile) AS max_epss_percentile,
			BOOL_OR(COALESCE(e.kev_listed, false)) AS kev_listed,
			MAX(e.kev_date_added) AS kev_date_added,
			BOOL_OR(COALESCE(e.exploit_exists, false)) AS exploit_exists,
			MAX(f.created_at) AS last_seen
		FROM findings f
		JOIN scans s ON s.id = f.scan_id
		JOIN images i ON i.id = s.image_id
		JOIN registries r ON r.id = i.registry_id
		LEFT JOIN enrichments e ON e.finding_id = f.id
		WHERE f.vulnerability_id = $1
		  AND i.deleted_at IS NULL AND r.deleted_at IS NULL
		`+suppressionFilter+`
		GROUP BY f.vulnerability_id
	`, cveID).Scan(
		&d.VulnerabilityID, &d.Title, &d.Description, &d.Severity,
		&d.Occurrences, &d.RiskScore, &d.CVSSV3Score,
		&d.EPSSScore, &d.EPSSPercentile, &d.KEVListed,
		&d.KEVDateAdded, &d.ExploitExists, &d.LastSeen,
	)
	if err != nil {
		return d, err
	}

	// Fetch distinct data sources.
	dsRows, err := pool.Query(ctx, `
		SELECT DISTINCT f.data_source
		FROM findings f
		WHERE f.vulnerability_id = $1 AND f.data_source IS NOT NULL AND f.data_source != ''
	`, cveID)
	if err == nil {
		defer dsRows.Close()
		for dsRows.Next() {
			var src string
			if err := dsRows.Scan(&src); err == nil {
				d.DataSources = append(d.DataSources, src)
			}
		}
	}

	// Fetch affected images with fixed version candidates.
	imgRows, err := pool.Query(ctx, `
		SELECT DISTINCT ON (i.id) i.id, i.repository, i.tag,
		       (SELECT f2.fixed_version FROM findings f2
		        WHERE f2.vulnerability_id = $1
		          AND f2.scan_id = s.id
		          AND f2.fixed_version IS NOT NULL
		          AND f2.fixed_version != ''
		        LIMIT 1) AS fixed_version
		FROM findings f
		JOIN scans s ON s.id = f.scan_id
		JOIN images i ON i.id = s.image_id
		JOIN registries r ON r.id = i.registry_id
		WHERE f.vulnerability_id = $1 AND i.deleted_at IS NULL AND r.deleted_at IS NULL
		ORDER BY i.id, i.repository, i.tag, s.started_at DESC
	`, cveID)
	if err == nil {
		defer imgRows.Close()
		for imgRows.Next() {
			var img CVEImageSummary
			var fixed *string
			if err := imgRows.Scan(&img.ImageID, &img.Repository, &img.Tag, &fixed); err == nil {
				if fixed != nil {
					img.FixedVer = *fixed
				}
				d.AffectedImages = append(d.AffectedImages, img)
			}
		}
	}

	return d, nil
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
