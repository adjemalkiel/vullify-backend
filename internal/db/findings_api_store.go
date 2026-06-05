package db

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// FindingDetail includes finding + enrichment + scan/image context.
type FindingDetail struct {
	ID               uuid.UUID
	ScanID           uuid.UUID
	VulnerabilityID  string
	PackageName      string
	InstalledVersion *string
	FixedVersion     *string
	Severity         string
	Title            *string
	Description      *string
	DataSource       *string
	CreatedAt        time.Time
	EPSSScore        *float64
	EPSSPercentile   *float64
	KEVListed        bool
	KEVDateAdded     *time.Time
	KnownExploits    json.RawMessage
	ExploitExists    bool
	RiskScore        *float64
	EnrichedAt       *time.Time
	ImageRepository  string
	ImageTag         string
}

// GetFindingDetail returns a finding with enrichment by ID.
func GetFindingDetail(ctx context.Context, pool *pgxpool.Pool, findingID uuid.UUID) (FindingDetail, error) {
	var d FindingDetail
	err := pool.QueryRow(ctx, `
		SELECT
			f.id, f.scan_id, f.vulnerability_id, f.package_name, f.installed_version, f.fixed_version,
			f.severity::text, f.title, f.description, f.data_source, f.created_at,
			e.epss_score, e.epss_percentile, COALESCE(e.kev_listed, false), e.kev_date_added,
			e.known_exploits, COALESCE(e.exploit_exists, false), e.risk_score, e.enriched_at,
			i.repository, i.tag
		FROM findings f
		JOIN scans s ON s.id = f.scan_id
		JOIN images i ON i.id = s.image_id
		JOIN registries r ON r.id = i.registry_id
		LEFT JOIN enrichments e ON e.finding_id = f.id
		WHERE f.id = $1 AND i.deleted_at IS NULL AND r.deleted_at IS NULL
		`+suppressionFilter, findingID).Scan(
		&d.ID, &d.ScanID, &d.VulnerabilityID, &d.PackageName, &d.InstalledVersion, &d.FixedVersion,
		&d.Severity, &d.Title, &d.Description, &d.DataSource, &d.CreatedAt,
		&d.EPSSScore, &d.EPSSPercentile, &d.KEVListed, &d.KEVDateAdded,
		&d.KnownExploits, &d.ExploitExists, &d.RiskScore, &d.EnrichedAt,
		&d.ImageRepository, &d.ImageTag,
	)
	return d, err
}

// ImageIsActive checks image exists and registry not soft-deleted.
func ImageIsActive(ctx context.Context, pool *pgxpool.Pool, imageID uuid.UUID) (bool, error) {
	var n int
	err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM images i
		JOIN registries r ON r.id = i.registry_id
		WHERE i.id = $1 AND i.deleted_at IS NULL AND r.deleted_at IS NULL
	`, imageID).Scan(&n)
	return n > 0, err
}
