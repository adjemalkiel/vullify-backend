package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type epssRow struct {
	Score        *float64
	Percentile   *float64
}

// fetchEPSSBatched queries EPSS in batches of epssBatchSize. Failed batches are logged; partial results are kept.
func (e *Enricher) fetchEPSSBatched(ctx context.Context, cves []string) map[string]epssRow {
	log := e.Log
	if log == nil {
		log = slog.Default()
	}
	if len(cves) == 0 {
		return map[string]epssRow{}
	}

	seen := make(map[string]struct{})
	uniq := make([]string, 0, len(cves))
	for _, c := range cves {
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		uniq = append(uniq, c)
	}

	out := make(map[string]epssRow)
	base := e.EPSSBaseURL
	if base == "" {
		base = defaultEPSSBaseURL
	}

	for i := 0; i < len(uniq); i += epssBatchSize {
		end := i + epssBatchSize
		if end > len(uniq) {
			end = len(uniq)
		}
		chunk := uniq[i:end]
		if err := e.epssLimiter.Wait(ctx); err != nil {
			log.Warn("enrichment: epss rate limit wait", "err", err)
			break
		}

		batch, err := e.fetchEPSSOneBatch(ctx, base, chunk)
		if err != nil {
			log.Warn("enrichment: epss batch failed", "batch_size", len(chunk), "err", err)
			continue
		}
		for k, v := range batch {
			out[k] = v
		}
	}
	return out
}

func (e *Enricher) fetchEPSSOneBatch(ctx context.Context, base string, cves []string) (map[string]epssRow, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("cve", strings.Join(cves, ","))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
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
		return nil, fmt.Errorf("epss http %d", resp.StatusCode)
	}

	var envelope struct {
		Status string `json:"status"`
		Data   []struct {
			CVE        string          `json:"cve"`
			EPSS       json.RawMessage `json:"epss"`
			Percentile json.RawMessage `json:"percentile"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, err
	}

	out := make(map[string]epssRow)
	for _, r := range envelope.Data {
		cve := strings.TrimSpace(strings.ToUpper(r.CVE))
		if cve == "" {
			continue
		}
		s := parseFloatRaw(r.EPSS)
		p := parseFloatRaw(r.Percentile)
		out[cve] = epssRow{Score: s, Percentile: p}
	}
	return out, nil
}

func parseFloatRaw(raw json.RawMessage) *float64 {
	if len(raw) == 0 {
		return nil
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err == nil {
		return &f
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return nil
	}
	return &v
}
