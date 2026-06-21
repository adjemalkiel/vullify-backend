package db

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SoftDeleteImageTagsNotIn soft-deletes image rows for a repository whose tag is not in keepTags.
func SoftDeleteImageTagsNotIn(ctx context.Context, pool *pgxpool.Pool, registryID uuid.UUID, repository string, keepTags []string) error {
	if keepTags == nil {
		keepTags = []string{}
	}
	_, err := pool.Exec(ctx, `
		UPDATE images SET deleted_at = now()
		WHERE registry_id = $1 AND repository = $2 AND deleted_at IS NULL
		AND NOT (tag = ANY($3::text[]))
	`, registryID, repository, keepTags)
	return err
}

// SoftDeleteImagesForRepositoriesNotIn soft-deletes images whose repository is not in liveRepos.
// When liveRepos is empty, no images are deleted (prevents accidental mass deletion).
func SoftDeleteImagesForRepositoriesNotIn(ctx context.Context, pool *pgxpool.Pool, registryID uuid.UUID, liveRepos []string) error {
	if len(liveRepos) == 0 {
		return nil
	}
	_, err := pool.Exec(ctx, `
		UPDATE images SET deleted_at = now()
		WHERE registry_id = $1 AND deleted_at IS NULL
		AND repository NOT IN (SELECT unnest($2::text[]))
	`, registryID, liveRepos)
	return err
}

// InsertScheduledScan creates a pending scan triggered by schedule.
func InsertScheduledScan(ctx context.Context, pool *pgxpool.Pool, imageID uuid.UUID) (uuid.UUID, error) {
	var id uuid.UUID
	err := pool.QueryRow(ctx, `
		INSERT INTO scans (image_id, status, triggered_by)
		VALUES ($1, 'pending', 'schedule')
		RETURNING id
	`, imageID).Scan(&id)
	return id, err
}

// ImageHasPendingOrRunningScan is true when a non-terminal scan exists for the image.
func ImageHasPendingOrRunningScan(ctx context.Context, pool *pgxpool.Pool, imageID uuid.UUID) (bool, error) {
	var exists bool
	err := pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM scans
			WHERE image_id = $1 AND status IN ('pending', 'running')
		)
	`, imageID).Scan(&exists)
	return exists, err
}

// ListImageIDsStaleForRescan returns images whose latest completed scan ended before cutoff, or never had a completed scan.
func ListImageIDsStaleForRescan(ctx context.Context, pool *pgxpool.Pool, cutoff time.Time) ([]uuid.UUID, error) {
	rows, err := pool.Query(ctx, `
		SELECT i.id
		FROM images i
		JOIN registries r ON r.id = i.registry_id
		WHERE i.deleted_at IS NULL AND r.deleted_at IS NULL
		AND (
			NOT EXISTS (
				SELECT 1 FROM scans s
				WHERE s.image_id = i.id AND s.status = 'completed'
			)
			OR (
				(SELECT MAX(s.completed_at) FROM scans s
				 WHERE s.image_id = i.id AND s.status = 'completed') < $1
			)
		)
	`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ImageChangeRow is an active image with registry connector fields for digest checks.
type ImageChangeRow struct {
	ID           uuid.UUID
	RegistryID   uuid.UUID
	RegistryURL  string
	RegistryType string
	Credentials  json.RawMessage
	Repository   string
	Tag          string
	Digest       *string
}

// ListImagesForChangeDetection returns all active images with registry metadata.
func ListImagesForChangeDetection(ctx context.Context, pool *pgxpool.Pool) ([]ImageChangeRow, error) {
	rows, err := pool.Query(ctx, `
		SELECT i.id, i.registry_id, r.url, r."type"::text, r.credentials, i.repository, i.tag, i.digest
		FROM images i
		JOIN registries r ON r.id = i.registry_id
		WHERE i.deleted_at IS NULL AND r.deleted_at IS NULL
		ORDER BY i.registry_id, i.repository, i.tag
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ImageChangeRow
	for rows.Next() {
		var r ImageChangeRow
		if err := rows.Scan(
			&r.ID, &r.RegistryID, &r.RegistryURL, &r.RegistryType, &r.Credentials,
			&r.Repository, &r.Tag, &r.Digest,
		); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListActiveRegistries returns all non-deleted registries (for scheduler sync).
func ListActiveRegistries(ctx context.Context, pool *pgxpool.Pool) ([]RegistryRow, error) {
	rows, err := pool.Query(ctx, `
		SELECT id, name, "type"::text, url, credentials, created_at, updated_at, deleted_at
		FROM registries
		WHERE deleted_at IS NULL
		ORDER BY name ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RegistryRow
	for rows.Next() {
		var r RegistryRow
		if err := rows.Scan(&r.ID, &r.Name, &r.Type, &r.URL, &r.Credentials, &r.CreatedAt, &r.UpdatedAt, &r.DeletedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpdateImageDigest sets the digest column for an image (e.g. after a successful registry check).
func UpdateImageDigest(ctx context.Context, pool *pgxpool.Pool, imageID uuid.UUID, digest string) error {
	_, err := pool.Exec(ctx, `
		UPDATE images SET digest = $2 WHERE id = $1 AND deleted_at IS NULL
	`, imageID, digest)
	return err
}
