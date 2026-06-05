package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"golang.org/x/time/rate"

	"vullify/internal/db"
)

const (
	defaultEPSSBaseURL = "https://api.first.org/data/v1/epss"
	defaultKEVURL      = "https://www.cisa.gov/sites/default/files/feeds/known-exploited-vulnerabilities.json"
	defaultEventsChan  = "vullify:scan:events"
	defaultKEVRedisKey = "vullify:enrichment:kev_catalog"
	epssBatchSize      = 100
	kevCacheTTL        = 24 * time.Hour
)

// Enricher loads EPSS and CISA KEV data and persists enrichments.
type Enricher struct {
	Repo *db.Repository
	Redis *redis.Client

	HTTPClient *http.Client

	EPSSBaseURL   string
	KEVCatalogURL string
	EventsChannel string
	KEVRedisKey   string

	Log *slog.Logger

	epssLimiter *rate.Limiter
}

// NewEnricher returns an Enricher with defaults (10 EPSS requests/sec).
func NewEnricher(repo *db.Repository, rdb *redis.Client, log *slog.Logger) *Enricher {
	if log == nil {
		log = slog.Default()
	}
	return &Enricher{
		Repo:          repo,
		Redis:         rdb,
		HTTPClient:    http.DefaultClient,
		EPSSBaseURL:   defaultEPSSBaseURL,
		KEVCatalogURL: defaultKEVURL,
		EventsChannel: defaultEventsChan,
		KEVRedisKey:   defaultKEVRedisKey,
		Log:           log,
		epssLimiter:   rate.NewLimiter(rate.Limit(10), 1),
	}
}

func (e *Enricher) eventsChannel() string {
	if e.EventsChannel != "" {
		return e.EventsChannel
	}
	return defaultEventsChan
}

func (e *Enricher) kevRedisKey() string {
	if e.KEVRedisKey != "" {
		return e.KEVRedisKey
	}
	return defaultKEVRedisKey
}

// EnrichScan loads findings for the scan, fetches EPSS + KEV, and upserts enrichments.
// External API failures are logged; enrichment continues with partial data and does not return an error for API outages.
func (e *Enricher) EnrichScan(ctx context.Context, scanID uuid.UUID) error {
	findings, err := e.Repo.ListFindingsByScan(ctx, scanID)
	if err != nil {
		return fmt.Errorf("list findings: %w", err)
	}
	if len(findings) == 0 {
		e.Log.Info("enrichment: no findings for scan", "scan_id", scanID)
		return nil
	}

	cveList := make([]string, 0)
	for _, f := range findings {
		if c := normalizeCVE(f.VulnerabilityID); c != "" {
			cveList = append(cveList, c)
		}
	}

	epssByCVE := e.fetchEPSSBatched(ctx, cveList)

	kevByCVE, err := e.loadKEVCatalog(ctx)
	if err != nil {
		e.Log.Warn("enrichment: KEV catalog unavailable; treating all as not listed", "err", err)
		kevByCVE = nil
	}

	for _, f := range findings {
		cve := normalizeCVE(f.VulnerabilityID)
		var upsert db.EnrichmentUpsert
		upsert.FindingID = f.ID
		upsert.KEVListed = false

		if cve != "" {
			if row, ok := epssByCVE[cve]; ok {
				upsert.EPSSScore = row.Score
				upsert.EPSSPercentile = row.Percentile
			}
		}

		if cve != "" && kevByCVE != nil {
			if ent, ok := kevByCVE[cve]; ok {
				upsert.KEVListed = true
				t := ent.DateAdded
				upsert.KEVDateAdded = &t
				if b, err := json.Marshal(map[string]any{
					"source":          "CISA-KEV",
					"cve_id":          cve,
					"product":         ent.Product,
					"vendor_project":  ent.VendorProject,
					"vulnerability":   ent.VulnName,
				}); err == nil {
					upsert.KnownExploits = b
				}
			}
		}

		// --- Risk scoring ---
		var cvss float64
		if f.CVSSV3Score != nil {
			cvss = *f.CVSSV3Score
		}
		var epss float64
		if upsert.EPSSScore != nil {
			epss = *upsert.EPSSScore
		}
		// TODO: Integrate external exploit databases (e.g. nomi-sec PoC-in-GitHub) beyond KEV.
		hasExploit := upsert.KEVListed
		hasFix := f.FixedVersion != nil && *f.FixedVersion != ""
		score := CalculateRiskScore(cvss, epss, upsert.KEVListed, hasExploit, hasFix)
		upsert.ExploitExists = hasExploit
		upsert.RiskScore = &score

		if err := e.Repo.Upsert(ctx, upsert); err != nil {
			e.Log.Error("enrichment: upsert failed", "finding_id", f.ID, "err", err)
			continue
		}
	}

	e.Log.Info("enrichment: completed scan", "scan_id", scanID, "findings", len(findings))
	return nil
}

func normalizeCVE(v string) string {
	s := strings.TrimSpace(strings.ToUpper(v))
	if strings.HasPrefix(s, "CVE-") {
		return s
	}
	return ""
}
