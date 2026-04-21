package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Repository provides persistence helpers (enrichments, findings by scan).
type Repository struct {
	Pool *pgxpool.Pool
}

// NewRepository returns a Repository backed by pool.
func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{Pool: pool}
}

// FindingRef identifies a finding row for enrichment.
type FindingRef struct {
	ID              uuid.UUID
	VulnerabilityID string
}

// ListFindingsByScan returns findings for a completed scan.
func (r *Repository) ListFindingsByScan(ctx context.Context, scanID uuid.UUID) ([]FindingRef, error) {
	rows, err := r.Pool.Query(ctx, `
		SELECT id, vulnerability_id FROM findings WHERE scan_id = $1
	`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []FindingRef
	for rows.Next() {
		var f FindingRef
		if err := rows.Scan(&f.ID, &f.VulnerabilityID); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// EnrichmentUpsert is written to enrichments (insert or update on finding_id conflict).
type EnrichmentUpsert struct {
	FindingID        uuid.UUID
	EPSSScore        *float64
	EPSSPercentile   *float64
	KEVListed        bool
	KEVDateAdded     *time.Time
	KnownExploits    json.RawMessage // optional JSONB; nil → SQL NULL
}

// Upsert persists or updates enrichment for a finding.
func (r *Repository) Upsert(ctx context.Context, e EnrichmentUpsert) error {
	var kev interface{}
	if len(e.KnownExploits) > 0 {
		kev = e.KnownExploits
	}
	_, err := r.Pool.Exec(ctx, `
		INSERT INTO enrichments (
			finding_id, epss_score, epss_percentile, kev_listed, kev_date_added, known_exploits, enriched_at
		) VALUES (
			$1, $2, $3, $4, $5, $6::jsonb, now()
		)
		ON CONFLICT (finding_id) DO UPDATE SET
			epss_score = EXCLUDED.epss_score,
			epss_percentile = EXCLUDED.epss_percentile,
			kev_listed = EXCLUDED.kev_listed,
			kev_date_added = EXCLUDED.kev_date_added,
			known_exploits = EXCLUDED.known_exploits,
			enriched_at = now()
	`, e.FindingID, e.EPSSScore, e.EPSSPercentile, e.KEVListed, e.KEVDateAdded, kev)
	if err != nil {
		return fmt.Errorf("enrichment upsert: %w", err)
	}
	return nil
}
