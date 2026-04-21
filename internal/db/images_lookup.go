package db

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"vullify/internal/imageref"
)

// FindImageIDByPullRef finds an active image whose canonical pull reference matches want (case-insensitive).
func FindImageIDByPullRef(ctx context.Context, pool *pgxpool.Pool, want string) (uuid.UUID, error) {
	want = strings.TrimSpace(want)
	if want == "" {
		return uuid.Nil, pgx.ErrNoRows
	}
	wantLower := strings.ToLower(want)

	rows, err := pool.Query(ctx, `
		SELECT i.id, r.url, i.repository, i.tag
		FROM images i
		JOIN registries r ON r.id = i.registry_id
		WHERE i.deleted_at IS NULL AND r.deleted_at IS NULL
	`)
	if err != nil {
		return uuid.Nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var id uuid.UUID
		var url, repo, tag string
		if err := rows.Scan(&id, &url, &repo, &tag); err != nil {
			return uuid.Nil, err
		}
		ref := imageref.BuildImagePullRef(url, repo, tag)
		if strings.ToLower(ref) == wantLower {
			return id, nil
		}
	}
	if err := rows.Err(); err != nil {
		return uuid.Nil, err
	}
	return uuid.Nil, pgx.ErrNoRows
}
