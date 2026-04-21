package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

type kevEntry struct {
	DateAdded      time.Time
	VendorProject  string
	Product        string
	VulnName       string
}

// loadKEVCatalog returns a map of CVE ID -> KEV metadata, using Redis cache (24h TTL).
func (e *Enricher) loadKEVCatalog(ctx context.Context) (map[string]kevEntry, error) {
	key := e.kevRedisKey()
	if e.Redis != nil {
		b, err := e.Redis.Get(ctx, key).Bytes()
		if err == nil {
			return parseKEVJSON(b)
		}
		if err != redis.Nil {
			e.Log.Warn("enrichment: kev redis get", "err", err)
		}
	}

	u := e.KEVCatalogURL
	if u == "" {
		u = defaultKEVURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := e.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("kev http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 50<<20))
	if err != nil {
		return nil, err
	}

	if e.Redis != nil {
		if err := e.Redis.Set(ctx, key, body, kevCacheTTL).Err(); err != nil {
			e.Log.Warn("enrichment: kev redis set cache", "err", err)
		}
	}

	return parseKEVJSON(body)
}

func parseKEVJSON(body []byte) (map[string]kevEntry, error) {
	var feed struct {
		Vulnerabilities []struct {
			CVEID         string `json:"cveID"`
			DateAdded     string `json:"dateAdded"`
			VendorProject string `json:"vendorProject"`
			Product       string `json:"product"`
			VulnName      string `json:"vulnerabilityName"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &feed); err != nil {
		return nil, err
	}
	out := make(map[string]kevEntry)
	for _, v := range feed.Vulnerabilities {
		cve := strings.TrimSpace(strings.ToUpper(v.CVEID))
		if cve == "" {
			continue
		}
		t, _ := time.Parse("2006-01-02", strings.TrimSpace(v.DateAdded))
		out[cve] = kevEntry{
			DateAdded:     t,
			VendorProject: v.VendorProject,
			Product:       v.Product,
			VulnName:      v.VulnName,
		}
	}
	return out, nil
}
