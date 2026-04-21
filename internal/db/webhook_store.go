package db

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// InsertWebhookEvent stores the raw payload for auditing.
func InsertWebhookEvent(ctx context.Context, pool *pgxpool.Pool, source, eventType string, payload json.RawMessage) (uuid.UUID, error) {
	var id uuid.UUID
	err := pool.QueryRow(ctx, `
		INSERT INTO webhook_events (source, event_type, payload)
		VALUES ($1, $2, $3::jsonb)
		RETURNING id
	`, source, eventType, payload).Scan(&id)
	return id, err
}

// MarkWebhookEventProcessed sets processed=true after async handling succeeds.
func MarkWebhookEventProcessed(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID) error {
	_, err := pool.Exec(ctx, `UPDATE webhook_events SET processed = true WHERE id = $1`, id)
	return err
}

// InsertWebhookScan creates a pending scan triggered by webhook.
func InsertWebhookScan(ctx context.Context, pool *pgxpool.Pool, imageID uuid.UUID) (uuid.UUID, error) {
	var scanID uuid.UUID
	err := pool.QueryRow(ctx, `
		INSERT INTO scans (image_id, status, triggered_by)
		VALUES ($1, 'pending', 'webhook')
		RETURNING id
	`, imageID).Scan(&scanID)
	return scanID, err
}

// ListRegistriesByType returns active registries of the given type (e.g. dockerhub, gitlab, ghcr).
func ListRegistriesByType(ctx context.Context, pool *pgxpool.Pool, typ string) ([]RegistryRow, error) {
	rows, err := pool.Query(ctx, `
		SELECT id, name, "type"::text, url, credentials, created_at, updated_at, deleted_at
		FROM registries
		WHERE deleted_at IS NULL AND "type" = $1::registry_type
		ORDER BY name ASC
	`, typ)
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
