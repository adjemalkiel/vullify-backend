package integration_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"vullify/internal/api"
	"vullify/internal/db"
	"vullify/internal/enrichment"
	"vullify/internal/testutil"
)

// TestEnrichmentPipeline wires PostgreSQL + Redis (testcontainers), seeds a finding, runs the enricher
// against mocked EPSS/KEV HTTP endpoints, and verifies the dashboard API reflects stored state.
func TestEnrichmentPipeline(t *testing.T) {
	pool, c1 := testutil.PostgresPool(t)
	defer c1()
	rdb, c2 := testutil.RedisClient(t)
	defer c2()

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
	_, err = pool.Exec(ctx, `INSERT INTO images (id, registry_id, repository, tag) VALUES ($1,$2,'lib/p','1.0')`, imgID, regID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO scans (id, image_id, status, triggered_by) VALUES ($1,$2,'completed','manual')`, scanID, imgID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO findings (id, scan_id, vulnerability_id, package_name, severity)
		VALUES ($1, $2, 'CVE-2025-1', 'openssl', 'critical'::severity)
	`, fid, scanID)
	require.NoError(t, err)

	epss := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "OK",
			"data": []map[string]any{{
				"cve": "CVE-2025-1", "epss": 0.99, "percentile": 0.95,
			}},
		})
	}))
	t.Cleanup(epss.Close)
	kev := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2025-1","dateAdded":"2025-01-01","vendorProject":"v","product":"p","vulnerabilityName":"n"}]}`))
	}))
	t.Cleanup(kev.Close)

	e := enrichment.NewEnricher(db.NewRepository(pool), rdb, nil)
	e.HTTPClient = http.DefaultClient
	e.EPSSBaseURL = epss.URL
	e.KEVCatalogURL = kev.URL
	require.NoError(t, e.EnrichScan(ctx, scanID))

	srv := httptest.NewServer(api.NewHandler(pool, rdb))
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/api/v1/dashboard/summary")
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var dash struct {
		Data struct {
			TotalFindings int `json:"total_findings"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&dash))
	require.GreaterOrEqual(t, dash.Data.TotalFindings, 1)

	resp2, err := http.Get(srv.URL + "/api/v1/findings/" + fid.String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp2.Body.Close() })
	require.Equal(t, http.StatusOK, resp2.StatusCode)
	var finding struct {
		Data struct {
			EPSSScore *float64 `json:"epss_score"`
			KEVListed bool     `json:"kev_listed"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(resp2.Body).Decode(&finding))
	require.NotNil(t, finding.Data.EPSSScore)
	require.InDelta(t, 0.99, *finding.Data.EPSSScore, 0.001)
	require.True(t, finding.Data.KEVListed)
}
