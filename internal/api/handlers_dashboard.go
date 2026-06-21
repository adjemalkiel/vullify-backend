package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"vullify/internal/db"
)

func (s *Server) dashboardSummary(w http.ResponseWriter, r *http.Request) {
	sum, err := db.GetDashboardSummary(r.Context(), s.Pool)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load summary")
		return
	}
	writeEnvelope(w, http.StatusOK, map[string]any{
		"total_images":   sum.TotalImages,
		"total_scans":    sum.TotalScans,
		"total_findings": sum.TotalFindings,
		"by_severity":    sum.BySeverity,
	}, nil)
}

func (s *Server) vulnerabilityReport(w http.ResponseWriter, r *http.Request) {
	sev := strings.ToLower(r.URL.Query().Get("severity"))
	var from, to *time.Time
	if v := r.URL.Query().Get("from"); v != "" {
		t, err := time.Parse("2006-01-02", v)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid from date (YYYY-MM-DD)")
			return
		}
		from = &t
	}
	if v := r.URL.Query().Get("to"); v != "" {
		t, err := time.Parse("2006-01-02", v)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid to date (YYYY-MM-DD)")
			return
		}
		// inclusive end of day
		end := t.Add(24 * time.Hour)
		to = &end
	}
	page, perPage, offset := parsePagination(r)
	rows, total, err := db.ListVulnerabilityReport(r.Context(), s.Pool, sev, from, to, offset, perPage)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "report failed")
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		item := map[string]any{
			"vulnerability_id": row.VulnerabilityID,
			"severity":         row.Severity,
			"occurrences":      row.Occurrences,
		}
		if row.Title != "" {
			item["title"] = row.Title
		}
		if row.LastSeen != nil {
			item["last_seen"] = row.LastSeen.UTC().Format(timeRFC3339)
		}
		out = append(out, item)
	}
	writeEnvelope(w, http.StatusOK, out, &Meta{Page: page, PerPage: perPage, Total: int64(total)})
}

func (s *Server) globalCVEView(w http.ResponseWriter, r *http.Request) {
	sev := strings.ToLower(r.URL.Query().Get("severity"))
	sortBy := r.URL.Query().Get("sort_by")
	page, perPage, offset := parsePagination(r)

	var hasFix, isKEV *bool
	if v := r.URL.Query().Get("has_fix"); v != "" {
		b := strings.ToLower(v) == "true" || v == "1"
		hasFix = &b
	}
	if v := r.URL.Query().Get("is_kev"); v != "" {
		b := strings.ToLower(v) == "true" || v == "1"
		isKEV = &b
	}

	rows, total, err := db.ListGlobalCVEs(r.Context(), s.Pool, sev, sortBy, hasFix, isKEV, offset, perPage)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "list failed")
		return
	}

	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		item := map[string]any{
			"vulnerability_id": row.VulnerabilityID,
			"severity":         row.Severity,
			"occurrences":      row.Occurrences,
		}
		if row.Title != "" {
			item["title"] = row.Title
		}
		if row.MaxRiskScore != nil {
			item["risk_score"] = *row.MaxRiskScore
		}
		if row.LastSeen != nil {
			item["last_seen"] = row.LastSeen.UTC().Format(timeRFC3339)
		}
		out = append(out, item)
	}
	writeEnvelope(w, http.StatusOK, out, &Meta{Page: page, PerPage: perPage, Total: int64(total)})
}

func (s *Server) cveDetail(w http.ResponseWriter, r *http.Request) {
	cveID := r.PathValue("cve_id")
	if strings.TrimSpace(cveID) == "" {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "cve_id is required")
		return
	}
	d, err := db.GetCVEDetail(r.Context(), s.Pool, strings.TrimSpace(cveID))
	if err != nil {
		if err == pgx.ErrNoRows || d.VulnerabilityID == "" {
			writeAPIError(w, http.StatusNotFound, "NOT_FOUND", fmt.Sprintf("CVE %s not found", cveID))
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "load failed")
		return
	}

	m := map[string]any{
		"vulnerability_id": d.VulnerabilityID,
		"title":            d.Title,
		"description":      d.Description,
		"severity":         d.Severity,
		"occurrences":      d.Occurrences,
		"kev_listed":       d.KEVListed,
		"exploit_exists":   d.ExploitExists,
	}
	if d.RiskScore != nil {
		m["risk_score"] = *d.RiskScore
	}
	if d.CVSSV3Score != nil {
		m["cvss_v3_score"] = *d.CVSSV3Score
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
	if d.LastSeen != nil {
		m["last_seen"] = d.LastSeen.UTC().Format(timeRFC3339)
	}
	if len(d.DataSources) > 0 {
		m["data_sources"] = d.DataSources
	}
	if len(d.AffectedImages) > 0 {
		m["affected_images"] = d.AffectedImages
	} else {
		m["affected_images"] = []db.CVEImageSummary{}
	}
	writeEnvelope(w, http.StatusOK, m, nil)
}
