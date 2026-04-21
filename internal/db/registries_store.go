package db

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RegistryRow is a registry record (active rows have DeletedAt nil).
type RegistryRow struct {
	ID          uuid.UUID
	Name        string
	Type        string
	URL         string
	Credentials json.RawMessage
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   *time.Time
}

// InsertRegistry creates a registry.
func InsertRegistry(ctx context.Context, pool *pgxpool.Pool, name, typ, url string, credentials json.RawMessage) (uuid.UUID, error) {
	var id uuid.UUID
	err := pool.QueryRow(ctx, `
		INSERT INTO registries (name, "type", url, credentials)
		VALUES ($1, $2::registry_type, $3, $4::jsonb)
		RETURNING id
	`, name, typ, url, credentials).Scan(&id)
	return id, err
}

// ListRegistries returns non-deleted registries with total count.
func ListRegistries(ctx context.Context, pool *pgxpool.Pool, offset, limit int) ([]RegistryRow, int, error) {
	var total int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM registries WHERE deleted_at IS NULL`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := pool.Query(ctx, `
		SELECT id, name, "type"::text, url, credentials, created_at, updated_at, deleted_at
		FROM registries
		WHERE deleted_at IS NULL
		ORDER BY name ASC
		OFFSET $1 LIMIT $2
	`, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	return scanRegistryRows(rows, total)
}

func scanRegistryRows(rows pgx.Rows, total int) ([]RegistryRow, int, error) {
	var out []RegistryRow
	for rows.Next() {
		var r RegistryRow
		if err := rows.Scan(&r.ID, &r.Name, &r.Type, &r.URL, &r.Credentials, &r.CreatedAt, &r.UpdatedAt, &r.DeletedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// GetRegistryByID returns a registry or ErrNoRows.
func GetRegistryByID(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID) (RegistryRow, error) {
	var r RegistryRow
	err := pool.QueryRow(ctx, `
		SELECT id, name, "type"::text, url, credentials, created_at, updated_at, deleted_at
		FROM registries WHERE id = $1 AND deleted_at IS NULL
	`, id).Scan(&r.ID, &r.Name, &r.Type, &r.URL, &r.Credentials, &r.CreatedAt, &r.UpdatedAt, &r.DeletedAt)
	return r, err
}

// UpdateRegistry updates fields.
func UpdateRegistry(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID, name, typ, url string, credentials json.RawMessage) error {
	tag, err := pool.Exec(ctx, `
		UPDATE registries SET
			name = $2,
			"type" = $3::registry_type,
			url = $4,
			credentials = $5::jsonb,
			updated_at = now()
		WHERE id = $1 AND deleted_at IS NULL
	`, id, name, typ, url, credentials)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// SoftDeleteRegistry sets deleted_at on registry and its images.
func SoftDeleteRegistry(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `UPDATE images SET deleted_at = now() WHERE registry_id = $1 AND deleted_at IS NULL`, id); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE registries SET deleted_at = now(), updated_at = now() WHERE id = $1 AND deleted_at IS NULL`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return tx.Commit(ctx)
}

// UpsertImage inserts or updates an image row (by registry_id, repository, tag) for active rows.
func UpsertImage(ctx context.Context, pool *pgxpool.Pool, registryID uuid.UUID, repository, tag string) (uuid.UUID, error) {
	var id uuid.UUID
	err := pool.QueryRow(ctx, `
		SELECT id FROM images
		WHERE registry_id = $1 AND repository = $2 AND tag = $3 AND deleted_at IS NULL
	`, registryID, repository, tag).Scan(&id)
	if err == nil {
		_, err = pool.Exec(ctx, `UPDATE images SET last_seen_at = now() WHERE id = $1`, id)
		return id, err
	}
	if err != pgx.ErrNoRows {
		return uuid.Nil, err
	}
	err = pool.QueryRow(ctx, `
		INSERT INTO images (registry_id, repository, tag, first_seen_at, last_seen_at)
		VALUES ($1, $2, $3, now(), now())
		RETURNING id
	`, registryID, repository, tag).Scan(&id)
	return id, err
}
