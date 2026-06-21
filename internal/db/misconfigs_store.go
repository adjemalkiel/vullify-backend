package db

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MisconfigRow holds a row for batch insert into misconfigurations.
type MisconfigRow struct {
	Type        string
	CheckID     string
	Title       string
	Description string
	Severity    string
	Resolution  string
	FilePath    string
	StartLine   int
	EndLine     int
}

// ListMisconfigsForScan returns all misconfigurations for a scan.
func ListMisconfigsForScan(ctx context.Context, pool *pgxpool.Pool, scanID uuid.UUID) ([]MisconfigRow, error) {
	rows, err := pool.Query(ctx, `
		SELECT type, check_id, title, description, severity::text, resolution, file_path, start_line, end_line
		FROM misconfigurations
		WHERE scan_id = $1
		ORDER BY severity, title
	`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MisconfigRow
	for rows.Next() {
		var r MisconfigRow
		if err := rows.Scan(&r.Type, &r.CheckID, &r.Title, &r.Description, &r.Severity, &r.Resolution, &r.FilePath, &r.StartLine, &r.EndLine); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// MisconfigListRow includes the id for a paginated list response.
type MisconfigListRow struct {
	ID          uuid.UUID
	Type        string
	CheckID     string
	Title       string
	Description string
	Severity    string
	Resolution  string
	FilePath    string
	StartLine   int
	EndLine     int
}

// ListMisconfigsForScanPaginated returns misconfigurations for a scan with pagination and optional severity filter.
func ListMisconfigsForScanPaginated(ctx context.Context, pool *pgxpool.Pool, scanID uuid.UUID, severity string, offset, limit int) ([]MisconfigListRow, int, error) {
	q := `SELECT COUNT(*) FROM misconfigurations WHERE scan_id = $1`
	args := []any{scanID}
	argPos := 2
	if severity != "" {
		q += fmt.Sprintf(` AND severity = $%d::severity`, argPos)
		args = append(args, severity)
		argPos++
	}
	var total int
	if err := pool.QueryRow(ctx, q, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	listQ := `SELECT id, type, check_id, title, description, severity::text, resolution, file_path, start_line, end_line FROM misconfigurations WHERE scan_id = $1`
	listArgs := []any{scanID}
	lp := 2
	if severity != "" {
		listQ += fmt.Sprintf(` AND severity = $%d::severity`, lp)
		listArgs = append(listArgs, severity)
		lp++
	}
	listQ += fmt.Sprintf(` ORDER BY severity, title OFFSET $%d LIMIT $%d`, lp, lp+1)
	listArgs = append(listArgs, offset, limit)

	rows, err := pool.Query(ctx, listQ, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []MisconfigListRow
	for rows.Next() {
		var r MisconfigListRow
		if err := rows.Scan(&r.ID, &r.Type, &r.CheckID, &r.Title, &r.Description, &r.Severity, &r.Resolution, &r.FilePath, &r.StartLine, &r.EndLine); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// BatchInsertMisconfigs inserts misconfigurations for a scan in a single batch.
func BatchInsertMisconfigs(ctx context.Context, pool *pgxpool.Pool, scanID uuid.UUID, mcs []MisconfigRow) error {
	if len(mcs) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, m := range mcs {
		sev := normalizeSeverity(m.Severity)
		batch.Queue(`
			INSERT INTO misconfigurations (scan_id, type, check_id, title, description, severity, resolution, file_path, start_line, end_line)
			VALUES ($1, $2, $3, $4, $5, $6::severity, $7, $8, $9, $10)`,
			scanID, m.Type, m.CheckID, m.Title, m.Description, sev, nullIfEmpty(m.Resolution), nullIfEmpty(m.FilePath), m.StartLine, m.EndLine,
		)
	}
	br := pool.SendBatch(ctx, batch)
	defer br.Close()
	for i := 0; i < batch.Len(); i++ {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("misconfiguration row %d: %w", i, err)
		}
	}
	return nil
}
