package db_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"vullify/internal/db"
	"vullify/internal/testutil"
)

func TestRepository_ListFindingsByScan(t *testing.T) {
	pool, cleanup := testutil.PostgresPool(t)
	defer cleanup()
	ctx := context.Background()

	regID := uuid.New()
	imgID := uuid.New()
	scanID := uuid.New()
	f1 := uuid.New()
	f2 := uuid.New()

	_, err := pool.Exec(ctx, `
		INSERT INTO registries (id, name, "type", url, credentials)
		VALUES ($1, 'r1', 'dockerhub'::registry_type, 'https://registry-1.docker.io', '{}'::jsonb)
	`, regID)
	require.NoError(t, err)

	_, err = pool.Exec(ctx, `
		INSERT INTO images (id, registry_id, repository, tag)
		VALUES ($1, $2, 'lib/test', '1.0')
	`, imgID, regID)
	require.NoError(t, err)

	_, err = pool.Exec(ctx, `
		INSERT INTO scans (id, image_id, status, triggered_by)
		VALUES ($1, $2, 'completed', 'manual')
	`, scanID, imgID)
	require.NoError(t, err)

	_, err = pool.Exec(ctx, `
		INSERT INTO findings (id, scan_id, vulnerability_id, package_name, severity, title)
		VALUES
			($1, $3, 'CVE-2024-1', 'pkg-a', 'high'::severity, 'a'),
			($2, $3, 'CVE-2024-2', 'pkg-b', 'low'::severity, 'b')
	`, f1, f2, scanID)
	require.NoError(t, err)

	repo := db.NewRepository(pool)
	refs, err := repo.ListFindingsByScan(ctx, scanID)
	require.NoError(t, err)
	require.Len(t, refs, 2)
	seen := map[uuid.UUID]string{}
	for _, r := range refs {
		seen[r.ID] = r.VulnerabilityID
	}
	require.Equal(t, "CVE-2024-1", seen[f1])
	require.Equal(t, "CVE-2024-2", seen[f2])
}

func TestRepository_Upsert(t *testing.T) {
	pool, cleanup := testutil.PostgresPool(t)
	defer cleanup()
	ctx := context.Background()

	regID := uuid.New()
	imgID := uuid.New()
	scanID := uuid.New()
	fid := uuid.New()

	_, err := pool.Exec(ctx, `
		INSERT INTO registries (id, name, "type", url, credentials)
		VALUES ($1, 'r1', 'dockerhub'::registry_type, 'https://registry-1.docker.io', '{}'::jsonb)
	`, regID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO images (id, registry_id, repository, tag) VALUES ($1,$2,'x','y')`, imgID, regID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO scans (id, image_id, status, triggered_by) VALUES ($1,$2,'completed','manual')`, scanID, imgID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO findings (id, scan_id, vulnerability_id, package_name, severity)
		VALUES ($1, $2, 'CVE-2020-1', 'p', 'medium'::severity)
	`, fid, scanID)
	require.NoError(t, err)

	repo := db.NewRepository(pool)
	score := 0.42
	pct := 0.99
	d := time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)
	kev := json.RawMessage(`{"source":"test"}`)
	err = repo.Upsert(ctx, db.EnrichmentUpsert{
		FindingID:      fid,
		EPSSScore:      &score,
		EPSSPercentile: &pct,
		KEVListed:      true,
		KEVDateAdded:   &d,
		KnownExploits:  kev,
	})
	require.NoError(t, err)

	var gotScore *float64
	var gotKev bool
	err = pool.QueryRow(ctx, `
		SELECT epss_score, kev_listed FROM enrichments WHERE finding_id = $1
	`, fid).Scan(&gotScore, &gotKev)
	require.NoError(t, err)
	require.NotNil(t, gotScore)
	require.InDelta(t, 0.42, *gotScore, 0.001)
	require.True(t, gotKev)

	score2 := 0.5
	err = repo.Upsert(ctx, db.EnrichmentUpsert{
		FindingID: fid,
		EPSSScore: &score2,
		KEVListed: false,
	})
	require.NoError(t, err)
	err = pool.QueryRow(ctx, `SELECT epss_score, kev_listed FROM enrichments WHERE finding_id = $1`, fid).Scan(&gotScore, &gotKev)
	require.NoError(t, err)
	require.InDelta(t, 0.5, *gotScore, 0.001)
	require.False(t, gotKev)
}
