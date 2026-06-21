package db

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SecretRow holds a row for batch insert into secrets.
type SecretRow struct {
	RuleID      string
	Category    string
	Severity    string
	Title       string
	MatchText   string
	FilePath    string
	StartLine   int
	EndLine     int
	LayerDigest string
}

// ListSecretsForScan returns all secrets for a scan.
func ListSecretsForScan(ctx context.Context, pool *pgxpool.Pool, scanID uuid.UUID) ([]SecretRow, error) {
	rows, err := pool.Query(ctx, `
		SELECT rule_id, category, severity::text, title, match_text, file_path, start_line, end_line, layer_digest
		FROM secrets
		WHERE scan_id = $1
		ORDER BY severity, title
	`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SecretRow
	for rows.Next() {
		var r SecretRow
		if err := rows.Scan(&r.RuleID, &r.Category, &r.Severity, &r.Title, &r.MatchText, &r.FilePath, &r.StartLine, &r.EndLine, &r.LayerDigest); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SecretListRow includes the id for a paginated list response.
type SecretListRow struct {
	ID          uuid.UUID
	RuleID      string
	Category    string
	Severity    string
	Title       string
	MatchText   string
	FilePath    string
	StartLine   int
	EndLine     int
	LayerDigest string
}

// ListSecretsForScanPaginated returns secrets for a scan with pagination and optional severity filter.
func ListSecretsForScanPaginated(ctx context.Context, pool *pgxpool.Pool, scanID uuid.UUID, severity string, offset, limit int) ([]SecretListRow, int, error) {
	q := `SELECT COUNT(*) FROM secrets WHERE scan_id = $1`
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

	listQ := `SELECT id, rule_id, category, severity::text, title, match_text, file_path, start_line, end_line, layer_digest FROM secrets WHERE scan_id = $1`
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

	var out []SecretListRow
	for rows.Next() {
		var r SecretListRow
		if err := rows.Scan(&r.ID, &r.RuleID, &r.Category, &r.Severity, &r.Title, &r.MatchText, &r.FilePath, &r.StartLine, &r.EndLine, &r.LayerDigest); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// BatchInsertSecrets inserts secrets for a scan in a single batch.
func BatchInsertSecrets(ctx context.Context, pool *pgxpool.Pool, scanID uuid.UUID, secs []SecretRow) error {
	if len(secs) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, s := range secs {
		sev := normalizeSeverity(s.Severity)
		batch.Queue(`
			INSERT INTO secrets (scan_id, rule_id, category, severity, title, match_text, file_path, start_line, end_line, layer_digest)
			VALUES ($1, $2, $3, $4::severity, $5, $6, $7, $8, $9, $10)`,
			scanID, s.RuleID, s.Category, sev, nullIfEmpty(s.Title), s.MatchText, nullIfEmpty(s.FilePath), s.StartLine, s.EndLine, nullIfEmpty(s.LayerDigest),
		)
	}
	br := pool.SendBatch(ctx, batch)
	defer br.Close()
	for i := 0; i < batch.Len(); i++ {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("secret row %d: %w", i, err)
		}
	}
	return nil
}
