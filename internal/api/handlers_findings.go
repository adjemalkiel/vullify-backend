package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"vullify/internal/db"
)

func (s *Server) getFinding(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid id")
		return
	}
	d, err := db.GetFindingDetail(r.Context(), s.Pool, id)
	if err != nil {
		if err == pgx.ErrNoRows {
			writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "finding not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "load failed")
		return
	}
	m := map[string]any{
		"id": d.ID.String(), "scan_id": d.ScanID.String(),
		"vulnerability_id": d.VulnerabilityID, "package_name": d.PackageName,
		"severity": d.Severity, "created_at": d.CreatedAt.UTC().Format(timeRFC3339),
		"kev_listed": d.KEVListed,
		"image": map[string]string{"repository": d.ImageRepository, "tag": d.ImageTag},
	}
	if d.InstalledVersion != nil {
		m["installed_version"] = *d.InstalledVersion
	}
	if d.FixedVersion != nil {
		m["fixed_version"] = *d.FixedVersion
	}
	if d.Title != nil {
		m["title"] = *d.Title
	}
	if d.Description != nil {
		m["description"] = *d.Description
	}
	if d.DataSource != nil {
		m["data_source"] = *d.DataSource
	}
	if d.EPSSScore != nil {
		m["epss_score"] = *d.EPSSScore
	}
	if d.EPSSPercentile != nil {
		m["epss_percentile"] = *d.EPSSPercentile
	}
	if d.KEVDateAdded != nil {
		m["kev_date_added"] = d.KEVDateAdded.Format("2006-01-02")
	}
	if len(d.KnownExploits) > 0 {
		var v any
		if err := json.Unmarshal(d.KnownExploits, &v); err == nil {
			m["known_exploits"] = v
		}
	}
	if d.EnrichedAt != nil {
		m["enriched_at"] = d.EnrichedAt.UTC().Format(timeRFC3339)
	}
	writeEnvelope(w, http.StatusOK, m, nil)
}
