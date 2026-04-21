package enrichment

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"vullify/internal/db"
	"vullify/internal/testutil"
)

func TestEnricher_EnrichScan(t *testing.T) {
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
		VALUES ($1, $2, 'CVE-2024-99999', 'p', 'high'::severity)
	`, fid, scanID)
	require.NoError(t, err)

	epssSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cve") != "CVE-2024-99999" {
			t.Errorf("unexpected cve query: %q", r.URL.Query().Get("cve"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "OK",
			"data": []map[string]any{
				{
					"cve":        "CVE-2024-99999",
					"epss":       0.42,
					"percentile": 0.9,
				},
			},
		})
	}))
	t.Cleanup(epssSrv.Close)

	kevBody := `{
  "vulnerabilities": [
    {
      "cveID": "CVE-2024-99999",
      "dateAdded": "2024-06-01",
      "vendorProject": "vendor",
      "product": "prod",
      "vulnerabilityName": "Test"
    }
  ]
}`
	kevSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(kevBody))
	}))
	t.Cleanup(kevSrv.Close)

	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	e := NewEnricher(db.NewRepository(pool), rdb, nil)
	e.HTTPClient = http.DefaultClient
	e.EPSSBaseURL = epssSrv.URL
	e.KEVCatalogURL = kevSrv.URL

	require.NoError(t, e.EnrichScan(ctx, scanID))

	var score *float64
	var kev bool
	err = pool.QueryRow(ctx, `SELECT epss_score, kev_listed FROM enrichments WHERE finding_id = $1`, fid).Scan(&score, &kev)
	require.NoError(t, err)
	require.NotNil(t, score)
	require.InDelta(t, 0.42, *score, 0.001)
	require.True(t, kev)
}
