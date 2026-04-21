package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"vullify/internal/testutil"
)

func TestAPI_DashboardSummary_Empty(t *testing.T) {
	pool, cleanup := testutil.PostgresPool(t)
	defer cleanup()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	srv := httptest.NewServer(NewHandler(pool, rdb))
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/dashboard/summary", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var env struct {
		Data map[string]any `json:"data"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&env))
	require.NotNil(t, env.Data)
}

func TestAPI_ListRegistries_Empty(t *testing.T) {
	pool, cleanup := testutil.PostgresPool(t)
	defer cleanup()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	srv := httptest.NewServer(NewHandler(pool, rdb))
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/api/v1/registries?page=1&per_page=20")
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	require.Contains(t, string(body), `"data"`)
}
