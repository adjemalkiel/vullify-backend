package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"vullify/internal/db"
)

type createSuppressionReq struct {
	CVEID     string     `json:"cve_id"`
	PkgName   string     `json:"pkg_name"`
	ImageID   *string    `json:"image_id"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at"`
}

type updateSuppressionReq struct {
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// suppressionRowToMap converts a db.SuppressionRow to the API response map.
func suppressionRowToMap(sup *db.SuppressionRow) map[string]any {
	m := map[string]any{
		"id":         sup.ID.String(),
		"reason":     sup.Reason,
		"created_at": sup.CreatedAt.UTC().Format(timeRFC3339),
		"updated_at": sup.UpdatedAt.UTC().Format(timeRFC3339),
	}
	if sup.CVEID != nil {
		m["cve_id"] = *sup.CVEID
	}
	if sup.PkgName != nil {
		m["pkg_name"] = *sup.PkgName
	}
	if sup.ImageID != nil {
		m["image_id"] = sup.ImageID.String()
	}
	if sup.AcceptedBy != nil && *sup.AcceptedBy != "" {
		m["accepted_by"] = *sup.AcceptedBy
	}
	if sup.ExpiresAt != nil {
		m["expires_at"] = sup.ExpiresAt.UTC().Format(timeRFC3339)
	}
	return m
}

func (s *Server) listSuppressions(w http.ResponseWriter, r *http.Request) {
	page, perPage, offset := parsePagination(r)
	rows, total, err := db.ListSuppressions(r.Context(), s.Pool, offset, perPage)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "list failed")
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for i := range rows {
		out = append(out, suppressionRowToMap(&rows[i]))
	}
	writeEnvelope(w, http.StatusOK, out, &Meta{Page: page, PerPage: perPage, Total: int64(total)})
}

func (s *Server) createSuppression(w http.ResponseWriter, r *http.Request) {
	var req createSuppressionReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid JSON body")
		return
	}
	if req.Reason == "" {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "reason is required")
		return
	}
	if req.CVEID == "" && req.PkgName == "" {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "cve_id or pkg_name is required")
		return
	}

	var imageID *uuid.UUID
	if req.ImageID != nil && *req.ImageID != "" {
		uid, err := uuid.Parse(*req.ImageID)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid image_id")
			return
		}
		imageID = &uid
	}

	id, err := db.InsertSuppression(r.Context(), s.Pool, req.CVEID, req.PkgName, imageID, req.Reason, "", req.ExpiresAt)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create suppression")
		return
	}

	sup, err := db.GetSuppressionByID(r.Context(), s.Pool, id)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load suppression")
		return
	}

	writeEnvelope(w, http.StatusCreated, suppressionRowToMap(sup), nil)
}

func (s *Server) updateSuppression(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid id")
		return
	}

	var req updateSuppressionReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid JSON body")
		return
	}

	sup, err := db.UpdateSuppression(r.Context(), s.Pool, id, req.Reason, req.ExpiresAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "suppression not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
		return
	}

	writeEnvelope(w, http.StatusOK, suppressionRowToMap(sup), nil)
}

func (s *Server) deleteSuppression(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid id")
		return
	}
	if err := db.DeleteSuppression(r.Context(), s.Pool, id); err != nil {
		if err == pgx.ErrNoRows {
			writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "suppression not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "delete failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
