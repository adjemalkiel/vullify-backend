package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"vullify/internal/db"
)

type imageResp struct {
	ID          string `json:"id"`
	RegistryID  string `json:"registry_id"`
	Repository  string `json:"repository"`
	Tag         string `json:"tag"`
	Digest      *string `json:"digest,omitempty"`
	FirstSeenAt string `json:"first_seen_at"`
	LastSeenAt  string `json:"last_seen_at"`
}

type imageDetailResp struct {
	imageResp
	RegistryURL          string  `json:"registry_url"`
	LatestScanID         *string `json:"latest_scan_id,omitempty"`
	LatestScanStatus     *string `json:"latest_scan_status,omitempty"`
	LatestScanStartedAt  *string `json:"latest_scan_started_at,omitempty"`
	LatestScanCompletedAt *string `json:"latest_scan_completed_at,omitempty"`
}

func (s *Server) listImages(w http.ResponseWriter, r *http.Request) {
	page, perPage, offset := parsePagination(r)
	var regID *uuid.UUID
	if v := r.URL.Query().Get("registry_id"); v != "" {
		u, err := uuid.Parse(v)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid registry_id")
			return
		}
		regID = &u
	}
	rows, total, err := db.ListImages(r.Context(), s.Pool, regID, offset, perPage)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "list failed")
		return
	}
	out := make([]imageResp, 0, len(rows))
	for _, im := range rows {
		out = append(out, imageResp{
			ID: im.ID.String(), RegistryID: im.RegistryID.String(),
			Repository: im.Repository, Tag: im.Tag, Digest: im.Digest,
			FirstSeenAt: im.FirstSeenAt.UTC().Format(timeRFC3339),
			LastSeenAt:  im.LastSeenAt.UTC().Format(timeRFC3339),
		})
	}
	writeEnvelope(w, http.StatusOK, out, &Meta{Page: page, PerPage: perPage, Total: int64(total)})
}

const timeRFC3339 = "2006-01-02T15:04:05Z07:00"

func (s *Server) getImage(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid id")
		return
	}
	d, err := db.GetImageByID(r.Context(), s.Pool, id)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "image not found")
		return
	}
	resp := imageDetailResp{
		imageResp: imageResp{
			ID: d.ID.String(), RegistryID: d.RegistryID.String(),
			Repository: d.Repository, Tag: d.Tag, Digest: d.Digest,
			FirstSeenAt: d.FirstSeenAt.UTC().Format(timeRFC3339),
			LastSeenAt:  d.LastSeenAt.UTC().Format(timeRFC3339),
		},
		RegistryURL: d.RegistryURL,
	}
	if d.LatestScanID != nil {
		sid := d.LatestScanID.String()
		resp.LatestScanID = &sid
	}
	resp.LatestScanStatus = d.LatestScanStatus
	if d.LatestScanStarted != nil {
		t := d.LatestScanStarted.UTC().Format(timeRFC3339)
		resp.LatestScanStartedAt = &t
	}
	if d.LatestScanCompleted != nil {
		t := d.LatestScanCompleted.UTC().Format(timeRFC3339)
		resp.LatestScanCompletedAt = &t
	}
	writeEnvelope(w, http.StatusOK, resp, nil)
}

func (s *Server) deleteImage(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid id")
		return
	}
	if err := db.SoftDeleteImage(r.Context(), s.Pool, id); err != nil {
		writeAPIError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
