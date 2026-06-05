package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"vullify/internal/db"
	"vullify/internal/imageref"
	"vullify/internal/scanqueue"
)

type createScanReq struct {
	ImageID   string `json:"image_id"`
	ImageRef  string `json:"image_ref"` // alternative to image_id: canonical pull ref matching stored images
}

type scanResp struct {
	ID           string  `json:"id"`
	ImageID      string  `json:"image_id"`
	Status       string  `json:"status"`
	TriggeredBy  string  `json:"triggered_by"`
	StartedAt    *string `json:"started_at,omitempty"`
	CompletedAt  *string `json:"completed_at,omitempty"`
	ErrorMessage *string `json:"error_message,omitempty"`
	TrivyVersion *string `json:"trivy_version,omitempty"`
	Repository   string  `json:"repository"`
	Tag          string  `json:"tag"`
}

type scanDetailResp struct {
	scanResp
	SeverityCounts map[string]int64 `json:"severity_counts"`
}

func ptrTime(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format(timeRFC3339)
	return &s
}

func (s *Server) createScan(w http.ResponseWriter, r *http.Request) {
	var req createScanReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid JSON body")
		return
	}
	var imgID uuid.UUID
	var err error
	switch {
	case strings.TrimSpace(req.ImageID) != "":
		imgID, err = uuid.Parse(strings.TrimSpace(req.ImageID))
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid image_id")
			return
		}
	case strings.TrimSpace(req.ImageRef) != "":
		imgID, err = db.FindImageIDByPullRef(r.Context(), s.Pool, req.ImageRef)
		if err == pgx.ErrNoRows {
			writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "no image matches image_ref")
			return
		}
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "lookup failed")
			return
		}
	default:
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "image_id or image_ref is required")
		return
	}
	ok, err := db.ImageIsActive(r.Context(), s.Pool, imgID)
	if err != nil || !ok {
		writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "image not found")
		return
	}
	d, err := db.GetImageByID(r.Context(), s.Pool, imgID)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "image not found")
		return
	}
	scanID, err := db.InsertManualScan(r.Context(), s.Pool, imgID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create scan")
		return
	}
	ref := imageref.BuildImagePullRef(d.RegistryURL, d.Repository, d.Tag)
	if err := scanqueue.Enqueue(r.Context(), s.Redis, s.queueKey(), scanID, ref); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to enqueue scan")
		return
	}
	detail, err := db.GetScanDetail(r.Context(), s.Pool, scanID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load scan")
		return
	}
	writeEnvelope(w, http.StatusCreated, scanDetailToResp(detail), nil)
}

func scanDetailToResp(d db.ScanDetail) scanDetailResp {
	return scanDetailResp{
		scanResp: scanResp{
			ID: d.ID.String(), ImageID: d.ImageID.String(),
			Status: d.Status, TriggeredBy: d.TriggeredBy,
			StartedAt: ptrTime(d.StartedAt), CompletedAt: ptrTime(d.CompletedAt),
			ErrorMessage: d.ErrorMessage, TrivyVersion: d.TrivyVersion,
			Repository: d.Repository, Tag: d.Tag,
		},
		SeverityCounts: d.SeverityCount,
	}
}

type scanListRow struct {
	ID            string           `json:"id"`
	ImageID       string           `json:"image_id"`
	Status        string           `json:"status"`
	TriggeredBy   string           `json:"triggered_by"`
	StartedAt     *string          `json:"started_at,omitempty"`
	CompletedAt   *string          `json:"completed_at,omitempty"`
	ErrorMessage  *string          `json:"error_message,omitempty"`
	TrivyVersion  *string          `json:"trivy_version,omitempty"`
	Repository    string           `json:"repository"`
	Tag           string           `json:"tag"`
	SeverityCounts map[string]int64 `json:"severity_counts"`
}

func scanRowToResp(r db.ScanRow) scanListRow {
	counts := make(map[string]int64)
	if r.CriticalCount > 0 {
		counts["critical"] = r.CriticalCount
	}
	if r.HighCount > 0 {
		counts["high"] = r.HighCount
	}
	if r.MediumCount > 0 {
		counts["medium"] = r.MediumCount
	}
	if r.LowCount > 0 {
		counts["low"] = r.LowCount
	}
	if r.UnknownCount > 0 {
		counts["unknown"] = r.UnknownCount
	}
	return scanListRow{
		ID: r.ID.String(), ImageID: r.ImageID.String(),
		Status: r.Status, TriggeredBy: r.TriggeredBy,
		StartedAt: ptrTime(r.StartedAt), CompletedAt: ptrTime(r.CompletedAt),
		ErrorMessage: r.ErrorMessage, TrivyVersion: r.TrivyVersion,
		Repository: r.Repository, Tag: r.Tag,
		SeverityCounts: counts,
	}
}

func (s *Server) listScans(w http.ResponseWriter, r *http.Request) {
	page, perPage, offset := parsePagination(r)
	status := r.URL.Query().Get("status")
	rows, total, err := db.ListScans(r.Context(), s.Pool, status, offset, perPage)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "list failed: "+err.Error())
		return
	}
	out := make([]scanListRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, scanRowToResp(row))
	}
	writeEnvelope(w, http.StatusOK, out, &Meta{Page: page, PerPage: perPage, Total: int64(total)})
}

func (s *Server) getScan(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid id")
		return
	}
	d, err := db.GetScanDetail(r.Context(), s.Pool, id)
	if err != nil {
		if err == pgx.ErrNoRows {
			writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "scan not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "load failed")
		return
	}
	writeEnvelope(w, http.StatusOK, scanDetailToResp(d), nil)
}

func (s *Server) listScanFindings(w http.ResponseWriter, r *http.Request) {
	scanID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid id")
		return
	}
	page, perPage, offset := parsePagination(r)
	sev := strings.ToLower(r.URL.Query().Get("severity"))
	pkg := r.URL.Query().Get("package_name")
	sort := r.URL.Query().Get("sort")
	rows, total, err := db.ListFindingsForScan(r.Context(), s.Pool, scanID, sev, pkg, sort, offset, perPage)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "list failed")
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, f := range rows {
		m := map[string]any{
			"id": f.ID.String(), "vulnerability_id": f.VulnerabilityID,
			"package_name": f.PackageName, "severity": f.Severity,
			"created_at": f.CreatedAt.UTC().Format(timeRFC3339),
		}
		if f.InstalledVersion != nil {
			m["installed_version"] = *f.InstalledVersion
		}
		if f.FixedVersion != nil {
			m["fixed_version"] = *f.FixedVersion
		}
		if f.Title != nil {
			m["title"] = *f.Title
		}
		out = append(out, m)
	}
	writeEnvelope(w, http.StatusOK, out, &Meta{Page: page, PerPage: perPage, Total: int64(total)})
}

func (s *Server) getScanSBOM(w http.ResponseWriter, r *http.Request) {
	scanID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid id")
		return
	}
	raw, format, err := db.GetSBOMForScan(r.Context(), s.Pool, scanID)
	if err != nil {
		if err == pgx.ErrNoRows {
			writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "sbom not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "load failed")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-SBOM-Format", format)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
