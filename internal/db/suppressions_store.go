package db

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SuppressionRow represents a row in the suppressions table.
type SuppressionRow struct {
	ID         uuid.UUID
	CVEID      *string
	PkgName    *string
	ImageID    *uuid.UUID
	Reason     string
	AcceptedBy *string
	ExpiresAt  *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// InsertSuppression creates a new suppression rule and returns its ID.
func InsertSuppression(ctx context.Context, pool *pgxpool.Pool, cveID, pkgName string, imageID *uuid.UUID, reason, acceptedBy string, expiresAt *time.Time) (uuid.UUID, error) {
	var id uuid.UUID
	err := pool.QueryRow(ctx, `
		INSERT INTO suppressions (cve_id, pkg_name, image_id, reason, accepted_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id
	`, nullIfEmpty(cveID), nullIfEmpty(pkgName), imageID, reason, nullIfEmpty(acceptedBy), expiresAt).Scan(&id)
	return id, err
}

// ListSuppressions returns suppressions with pagination.
func ListSuppressions(ctx context.Context, pool *pgxpool.Pool, offset, limit int) ([]SuppressionRow, int, error) {
	var total int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM suppressions`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := pool.Query(ctx, `
		SELECT id, cve_id, pkg_name, image_id, reason, accepted_by, expires_at, created_at, COALESCE(updated_at, created_at)
		FROM suppressions
		ORDER BY created_at DESC
		OFFSET $1 LIMIT $2
	`, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []SuppressionRow
	for rows.Next() {
		var r SuppressionRow
		if err := rows.Scan(&r.ID, &r.CVEID, &r.PkgName, &r.ImageID, &r.Reason, &r.AcceptedBy, &r.ExpiresAt, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// GetSuppressionByID returns a single suppression by ID.
func GetSuppressionByID(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID) (*SuppressionRow, error) {
	var r SuppressionRow
	err := pool.QueryRow(ctx, `
		SELECT id, cve_id, pkg_name, image_id, reason, accepted_by, expires_at, created_at, COALESCE(updated_at, created_at)
		FROM suppressions
		WHERE id = $1
	`, id).Scan(&r.ID, &r.CVEID, &r.PkgName, &r.ImageID, &r.Reason, &r.AcceptedBy, &r.ExpiresAt, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// UpdateSuppression updates reason and/or expires_at on an existing suppression.
// Returns the updated row or pgx.ErrNoRows if not found.
func UpdateSuppression(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID, reason string, expiresAt *time.Time) (*SuppressionRow, error) {
	var r SuppressionRow
	err := pool.QueryRow(ctx, `
		UPDATE suppressions
		SET reason = CASE WHEN $2::text != '' THEN $2::text ELSE reason END,
		    expires_at = COALESCE($3::timestamptz, expires_at),
		    updated_at = NOW()
		WHERE id = $1
		RETURNING id, cve_id, pkg_name, image_id, reason, accepted_by, expires_at, created_at, updated_at
	`, id, reason, expiresAt).Scan(&r.ID, &r.CVEID, &r.PkgName, &r.ImageID, &r.Reason, &r.AcceptedBy, &r.ExpiresAt, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// DeleteSuppression deletes a suppression by ID.
func DeleteSuppression(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID) error {
	tag, err := pool.Exec(ctx, `DELETE FROM suppressions WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}
