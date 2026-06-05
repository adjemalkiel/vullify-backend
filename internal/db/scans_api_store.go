package db

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ScanDetail for API.
type ScanDetail struct {
	ID            uuid.UUID
	ImageID       uuid.UUID
	Status        string
	TriggeredBy   string
	StartedAt     *time.Time
	CompletedAt   *time.Time
	ErrorMessage  *string
	TrivyVersion  *string
	Repository    string
	Tag           string
	SeverityCount map[string]int64
}

// ScanRow is a lightweight scan list row.
type ScanRow struct {
	ID            uuid.UUID
	ImageID       uuid.UUID
	Status        string
	TriggeredBy   string
	StartedAt     *time.Time
	CompletedAt   *time.Time
	ErrorMessage  *string
	TrivyVersion  *string
	Repository    string
	Tag           string
	CriticalCount int64
	HighCount     int64
	MediumCount   int64
	LowCount      int64
	UnknownCount  int64
}

// ListScans returns scans ordered by created_at DESC with optional status filter.
func ListScans(ctx context.Context, pool *pgxpool.Pool, status string, offset, limit int) ([]ScanRow, int, error) {
	var total int
	countQ := `SELECT COUNT(*) FROM scans s JOIN images i ON i.id = s.image_id JOIN registries r ON r.id = i.registry_id WHERE i.deleted_at IS NULL AND r.deleted_at IS NULL`
	args := []any{}
	argID := 1
	if status != "" {
		countQ += fmt.Sprintf(` AND s.status = $%d::scan_status`, argID)
		args = append(args, status)
		argID++
	}
	if err := pool.QueryRow(ctx, countQ, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	listQ := `SELECT s.id, s.image_id, s.status::text, s.triggered_by::text, s.started_at, s.completed_at, s.error_message, s.trivy_version, i.repository, i.tag, COALESCE(s.critical_count, 0), COALESCE(s.high_count, 0), COALESCE(s.medium_count, 0), COALESCE(s.low_count, 0), COALESCE(s.unknown_count, 0) FROM scans s JOIN images i ON i.id = s.image_id JOIN registries r ON r.id = i.registry_id WHERE i.deleted_at IS NULL AND r.deleted_at IS NULL`
	listArgs := []any{}
	laID := 1
	if status != "" {
		listQ += fmt.Sprintf(` AND s.status = $%d::scan_status`, laID)
		listArgs = append(listArgs, status)
		laID++
	}
	listQ += ` ORDER BY s.started_at DESC NULLS LAST` + fmt.Sprintf(` OFFSET $%d LIMIT $%d`, laID, laID+1)
	listArgs = append(listArgs, offset, limit)

	rows, err := pool.Query(ctx, listQ, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []ScanRow
	for rows.Next() {
		var r ScanRow
		if err := rows.Scan(&r.ID, &r.ImageID, &r.Status, &r.TriggeredBy, &r.StartedAt, &r.CompletedAt, &r.ErrorMessage, &r.TrivyVersion, &r.Repository, &r.Tag, &r.CriticalCount, &r.HighCount, &r.MediumCount, &r.LowCount, &r.UnknownCount); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// InsertManualScan creates a pending manual scan.
func InsertManualScan(ctx context.Context, pool *pgxpool.Pool, imageID uuid.UUID) (uuid.UUID, error) {
	var id uuid.UUID
	err := pool.QueryRow(ctx, `
		INSERT INTO scans (image_id, status, triggered_by)
		VALUES ($1, 'pending', 'manual')
		RETURNING id
	`, imageID).Scan(&id)
	return id, err
}

// GetScanDetail loads scan with image info and severity counts.
// Reads denormalized counts from the scan row when available; falls back to GROUP BY on findings.
func GetScanDetail(ctx context.Context, pool *pgxpool.Pool, scanID uuid.UUID) (ScanDetail, error) {
	var d ScanDetail
	d.SeverityCount = make(map[string]int64)
	var criticalCount, highCount, mediumCount, lowCount, unknownCount int64
	err := pool.QueryRow(ctx, `
		SELECT s.id, s.image_id, s.status::text, s.triggered_by::text, s.started_at, s.completed_at, s.error_message, s.trivy_version,
		       i.repository, i.tag,
		       COALESCE(s.critical_count, 0), COALESCE(s.high_count, 0), COALESCE(s.medium_count, 0), COALESCE(s.low_count, 0), COALESCE(s.unknown_count, 0)
		FROM scans s
		JOIN images i ON i.id = s.image_id
		JOIN registries r ON r.id = i.registry_id
		WHERE s.id = $1 AND i.deleted_at IS NULL AND r.deleted_at IS NULL
	`, scanID).Scan(
		&d.ID, &d.ImageID, &d.Status, &d.TriggeredBy, &d.StartedAt, &d.CompletedAt, &d.ErrorMessage, &d.TrivyVersion,
		&d.Repository, &d.Tag,
		&criticalCount, &highCount, &mediumCount, &lowCount, &unknownCount,
	)
	if err != nil {
		return d, err
	}

	if criticalCount > 0 {
		d.SeverityCount["critical"] = criticalCount
	}
	if highCount > 0 {
		d.SeverityCount["high"] = highCount
	}
	if mediumCount > 0 {
		d.SeverityCount["medium"] = mediumCount
	}
	if lowCount > 0 {
		d.SeverityCount["low"] = lowCount
	}
	if unknownCount > 0 {
		d.SeverityCount["unknown"] = unknownCount
	}

	if len(d.SeverityCount) == 0 {
		rows, err := pool.Query(ctx, `
			SELECT f.severity::text, COUNT(*)
			FROM findings f
			JOIN scans s ON s.id = f.scan_id
			JOIN images i ON i.id = s.image_id
			WHERE f.scan_id = $1
			`+suppressionFilter+`
			GROUP BY f.severity
		`, scanID)
		if err != nil {
			return d, err
		}
		defer rows.Close()
		for rows.Next() {
			var sev string
			var n int64
			if err := rows.Scan(&sev, &n); err != nil {
				return d, err
			}
			d.SeverityCount[sev] = n
		}
		if err := rows.Err(); err != nil {
			return d, err
		}
	}
	return d, nil
}

// FindingListRow for paginated findings.
type FindingListRow struct {
	ID               uuid.UUID
	VulnerabilityID  string
	PackageName      string
	InstalledVersion *string
	FixedVersion     *string
	Severity         string
	Title            *string
	CreatedAt        time.Time
}

// ListFindingsForScan lists findings with optional filters.
func ListFindingsForScan(ctx context.Context, pool *pgxpool.Pool, scanID uuid.UUID, severity, packageName, sort string, offset, limit int) ([]FindingListRow, int, error) {
	var total int
	q := `SELECT COUNT(*) FROM findings f
		JOIN scans s ON s.id = f.scan_id
		JOIN images i ON i.id = s.image_id
		WHERE f.scan_id = $1
		` + suppressionFilter
	args := []any{scanID}
	argPos := 2
	if severity != "" {
		q += fmt.Sprintf(` AND f.severity = $%d::severity`, argPos)
		args = append(args, severity)
		argPos++
	}
	if packageName != "" {
		q += fmt.Sprintf(` AND f.package_name ILIKE $%d`, argPos)
		args = append(args, "%"+packageName+"%")
	}
	if err := pool.QueryRow(ctx, q, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	order := "f.created_at DESC"
	switch strings.ToLower(sort) {
	case "severity":
		order = "f.severity ASC, f.created_at DESC"
	case "package_name":
		order = "f.package_name ASC, f.created_at DESC"
	case "created_at", "":
		order = "f.created_at DESC"
	}

	listQ := `SELECT f.id, f.vulnerability_id, f.package_name, f.installed_version, f.fixed_version, f.severity::text, f.title, f.created_at
		FROM findings f
		JOIN scans s ON s.id = f.scan_id
		JOIN images i ON i.id = s.image_id
		WHERE f.scan_id = $1
		` + suppressionFilter
	listArgs := []any{scanID}
	lp := 2
	if severity != "" {
		listQ += fmt.Sprintf(` AND f.severity = $%d::severity`, lp)
		listArgs = append(listArgs, severity)
		lp++
	}
	if packageName != "" {
		listQ += fmt.Sprintf(` AND f.package_name ILIKE $%d`, lp)
		listArgs = append(listArgs, "%"+packageName+"%")
		lp++
	}
	listQ += ` ORDER BY ` + order + fmt.Sprintf(` OFFSET $%d LIMIT $%d`, lp, lp+1)
	listArgs = append(listArgs, offset, limit)

	rows, err := pool.Query(ctx, listQ, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []FindingListRow
	for rows.Next() {
		var r FindingListRow
		if err := rows.Scan(&r.ID, &r.VulnerabilityID, &r.PackageName, &r.InstalledVersion, &r.FixedVersion, &r.Severity, &r.Title, &r.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// GetSBOMForScan returns SBOM JSON bytes and format.
func GetSBOMForScan(ctx context.Context, pool *pgxpool.Pool, scanID uuid.UUID) ([]byte, string, error) {
	var raw []byte
	var format string
	err := pool.QueryRow(ctx, `
		SELECT content, "format"::text FROM scan_sboms WHERE scan_id = $1 ORDER BY generated_at DESC LIMIT 1
	`, scanID).Scan(&raw, &format)
	if err != nil {
		return nil, "", err
	}
	return raw, format, err
}
