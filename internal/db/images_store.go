package db

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ImageRow is an image with registry join fields for API.
type ImageRow struct {
	ID          uuid.UUID
	RegistryID  uuid.UUID
	Repository  string
	Tag         string
	Digest      *string
	FirstSeenAt time.Time
	LastSeenAt  time.Time
}

// ListImages lists images with optional registry filter.
func ListImages(ctx context.Context, pool *pgxpool.Pool, registryID *uuid.UUID, offset, limit int) ([]ImageRow, int, error) {
	var total int
	var err error
	if registryID != nil {
		err = pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM images i
			JOIN registries r ON r.id = i.registry_id
			WHERE i.deleted_at IS NULL AND r.deleted_at IS NULL AND i.registry_id = $1
		`, *registryID).Scan(&total)
	} else {
		err = pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM images i
			JOIN registries r ON r.id = i.registry_id
			WHERE i.deleted_at IS NULL AND r.deleted_at IS NULL
		`).Scan(&total)
	}
	if err != nil {
		return nil, 0, err
	}

	var rows pgx.Rows
	if registryID != nil {
		rows, err = pool.Query(ctx, `
			SELECT i.id, i.registry_id, i.repository, i.tag, i.digest, i.first_seen_at, i.last_seen_at
			FROM images i
			JOIN registries r ON r.id = i.registry_id
			WHERE i.deleted_at IS NULL AND r.deleted_at IS NULL AND i.registry_id = $1
			ORDER BY i.last_seen_at DESC
			OFFSET $2 LIMIT $3
		`, *registryID, offset, limit)
	} else {
		rows, err = pool.Query(ctx, `
			SELECT i.id, i.registry_id, i.repository, i.tag, i.digest, i.first_seen_at, i.last_seen_at
			FROM images i
			JOIN registries r ON r.id = i.registry_id
			WHERE i.deleted_at IS NULL AND r.deleted_at IS NULL
			ORDER BY i.last_seen_at DESC
			OFFSET $1 LIMIT $2
		`, offset, limit)
	}
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []ImageRow
	for rows.Next() {
		var im ImageRow
		if err := rows.Scan(&im.ID, &im.RegistryID, &im.Repository, &im.Tag, &im.Digest, &im.FirstSeenAt, &im.LastSeenAt); err != nil {
			return nil, 0, err
		}
		out = append(out, im)
	}
	return out, total, rows.Err()
}

// ImageDetail includes registry URL for pull ref and latest scan summary.
type ImageDetail struct {
	ImageRow
	RegistryURL string
	// Latest scan (may be nil)
	LatestScanID        *uuid.UUID
	LatestScanStatus    *string
	LatestScanStarted   *time.Time
	LatestScanCompleted *time.Time
}

// GetImageByID returns image + registry url + latest scan.
func GetImageByID(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID) (ImageDetail, error) {
	var d ImageDetail
	err := pool.QueryRow(ctx, `
		SELECT i.id, i.registry_id, i.repository, i.tag, i.digest, i.first_seen_at, i.last_seen_at,
		       r.url
		FROM images i
		JOIN registries r ON r.id = i.registry_id
		WHERE i.id = $1 AND i.deleted_at IS NULL AND r.deleted_at IS NULL
	`, id).Scan(
		&d.ID, &d.RegistryID, &d.Repository, &d.Tag, &d.Digest, &d.FirstSeenAt, &d.LastSeenAt,
		&d.RegistryURL,
	)
	if err != nil {
		return d, err
	}

	var sid uuid.UUID
	var st string
	var sa, ca *time.Time
	switch err := pool.QueryRow(ctx, `
		SELECT s.id, s.status::text, s.started_at, s.completed_at
		FROM scans s
		WHERE s.image_id = $1
		ORDER BY s.id DESC
		LIMIT 1
	`, id).Scan(&sid, &st, &sa, &ca); err {
	case nil:
		d.LatestScanID = &sid
		d.LatestScanStatus = &st
		d.LatestScanStarted = sa
		d.LatestScanCompleted = ca
	case pgx.ErrNoRows:
	default:
		return d, err
	}
	return d, nil
}
