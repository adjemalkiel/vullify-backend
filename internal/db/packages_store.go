package db

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PackageRow holds a row for batch insert into packages.
type PackageRow struct {
	Name        string
	Version     string
	Type        string
	LayerDigest string
	Licenses    []string
	FilePath    string
}

// ListPackagesForScan returns all packages for a scan.
func ListPackagesForScan(ctx context.Context, pool *pgxpool.Pool, scanID uuid.UUID) ([]PackageRow, error) {
	rows, err := pool.Query(ctx, `
		SELECT name, version, type, layer_digest, licenses, file_path
		FROM packages
		WHERE scan_id = $1
		ORDER BY name
	`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PackageRow
	for rows.Next() {
		var r PackageRow
		if err := rows.Scan(&r.Name, &r.Version, &r.Type, &r.LayerDigest, &r.Licenses, &r.FilePath); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// PackageListRow includes the id for a paginated list response.
type PackageListRow struct {
	ID          uuid.UUID
	Name        string
	Version     string
	Type        string
	LayerDigest string
	Licenses    []string
	FilePath    string
}

// ListPackagesForScanPaginated returns packages for a scan with pagination and optional type filter.
func ListPackagesForScanPaginated(ctx context.Context, pool *pgxpool.Pool, scanID uuid.UUID, pkgType string, offset, limit int) ([]PackageListRow, int, error) {
	q := `SELECT COUNT(*) FROM packages WHERE scan_id = $1`
	args := []any{scanID}
	argPos := 2
	if pkgType != "" {
		q += fmt.Sprintf(` AND type = $%d`, argPos)
		args = append(args, pkgType)
		argPos++
	}
	var total int
	if err := pool.QueryRow(ctx, q, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	listQ := `SELECT id, name, version, type, layer_digest, licenses, file_path FROM packages WHERE scan_id = $1`
	listArgs := []any{scanID}
	lp := 2
	if pkgType != "" {
		listQ += fmt.Sprintf(` AND type = $%d`, lp)
		listArgs = append(listArgs, pkgType)
		lp++
	}
	listQ += fmt.Sprintf(` ORDER BY name OFFSET $%d LIMIT $%d`, lp, lp+1)
	listArgs = append(listArgs, offset, limit)

	rows, err := pool.Query(ctx, listQ, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []PackageListRow
	for rows.Next() {
		var r PackageListRow
		if err := rows.Scan(&r.ID, &r.Name, &r.Version, &r.Type, &r.LayerDigest, &r.Licenses, &r.FilePath); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// BatchInsertPackages inserts packages for a scan in a single batch.
func BatchInsertPackages(ctx context.Context, pool *pgxpool.Pool, scanID uuid.UUID, pkgs []PackageRow) error {
	if len(pkgs) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, p := range pkgs {
		batch.Queue(`
			INSERT INTO packages (scan_id, name, version, type, layer_digest, licenses, file_path)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			scanID, p.Name, p.Version, p.Type, nullIfEmpty(p.LayerDigest), p.Licenses, nullIfEmpty(p.FilePath),
		)
	}
	br := pool.SendBatch(ctx, batch)
	defer br.Close()
	for i := 0; i < batch.Len(); i++ {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("package row %d: %w", i, err)
		}
	}
	return nil
}
