package db

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Target represents a monitored image target.
type Target struct {
	ID             uuid.UUID
	ImageID        uuid.UUID
	ScanFrequency  string
	LatestScanID   *uuid.UUID
	LatestScanStatus *string
	CreatedAt      time.Time
	UpdatedAt      time.Time

	// Joined image fields for listing
	ImageRepository string
	ImageTag        string
	RegistryURL     string
	RegistryName    string
	SeverityCounts  map[string]int64
}

// CreateTarget inserts a new monitoring target.
func CreateTarget(ctx context.Context, pool *pgxpool.Pool, imageID uuid.UUID, scanFrequency string) (uuid.UUID, error) {
	if scanFrequency == "" {
		scanFrequency = "24h"
	}
	var id uuid.UUID
	err := pool.QueryRow(ctx, `
		INSERT INTO targets (image_id, scan_frequency) VALUES ($1, $2)
		RETURNING id
	`, imageID, scanFrequency).Scan(&id)
	return id, err
}

// ListTargets returns all active targets with their image info and latest scan summary.
func ListTargets(ctx context.Context, pool *pgxpool.Pool, severityMin string) ([]Target, error) {
	q := `
		SELECT
			t.id, t.image_id, t.scan_frequency, t.latest_scan_id, t.latest_scan_status,
			t.created_at, t.updated_at,
			i.repository, i.tag,
			r.url AS registry_url, r.name AS registry_name
		FROM targets t
		JOIN images i ON i.id = t.image_id
		JOIN registries r ON r.id = i.registry_id
		WHERE t.deleted_at IS NULL AND i.deleted_at IS NULL AND r.deleted_at IS NULL
		ORDER BY t.created_at DESC
	`
	rows, err := pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Target
	for rows.Next() {
		var tr Target
		if err := rows.Scan(&tr.ID, &tr.ImageID, &tr.ScanFrequency, &tr.LatestScanID,
			&tr.LatestScanStatus, &tr.CreatedAt, &tr.UpdatedAt,
			&tr.ImageRepository, &tr.ImageTag, &tr.RegistryURL, &tr.RegistryName); err != nil {
			return nil, err
		}
		tr.SeverityCounts = make(map[string]int64)
		out = append(out, tr)
	}
	return out, rows.Err()
}

// GetTargetByID returns a single target by ID.
func GetTargetByID(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID) (Target, error) {
	var tr Target
	err := pool.QueryRow(ctx, `
		SELECT
			t.id, t.image_id, t.scan_frequency, t.latest_scan_id, t.latest_scan_status,
			t.created_at, t.updated_at,
			i.repository, i.tag,
			r.url AS registry_url, r.name AS registry_name
		FROM targets t
		JOIN images i ON i.id = t.image_id
		JOIN registries r ON r.id = i.registry_id
		WHERE t.id = $1 AND t.deleted_at IS NULL
	`, id).Scan(&tr.ID, &tr.ImageID, &tr.ScanFrequency, &tr.LatestScanID,
		&tr.LatestScanStatus, &tr.CreatedAt, &tr.UpdatedAt,
		&tr.ImageRepository, &tr.ImageTag, &tr.RegistryURL, &tr.RegistryName)
	tr.SeverityCounts = make(map[string]int64)
	return tr, err
}

// UpdateTargetLatestScan sets the latest scan info on a target.
func UpdateTargetLatestScan(ctx context.Context, pool *pgxpool.Pool, targetID, scanID uuid.UUID, status string) error {
	_, err := pool.Exec(ctx, `
		UPDATE targets SET latest_scan_id = $2, latest_scan_status = $3, updated_at = now()
		WHERE id = $1 AND deleted_at IS NULL
	`, targetID, scanID, status)
	return err
}

// SoftDeleteTarget marks a target as deleted.
func SoftDeleteTarget(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID) error {
	tag, err := pool.Exec(ctx, `
		UPDATE targets SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL
	`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	return nil
}

// UpdateTarget updates the scan frequency of a target.
func UpdateTarget(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID, scanFrequency string) error {
	tag, err := pool.Exec(ctx, `
		UPDATE targets SET scan_frequency = $2, updated_at = now()
		WHERE id = $1 AND deleted_at IS NULL
	`, id, scanFrequency)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// TargetExists checks if a target already exists for an image (non-deleted).
func TargetExists(ctx context.Context, pool *pgxpool.Pool, imageID uuid.UUID) (bool, error) {
	var n int
	err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM targets WHERE image_id = $1 AND deleted_at IS NULL
	`, imageID).Scan(&n)
	return n > 0, err
}
