package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"vullify/internal/db"
	"vullify/internal/imageref"
	"vullify/internal/scanqueue"
)

type createTargetReq struct {
	ImageID       string `json:"image_id"`
	ScanFrequency string `json:"scan_frequency"` // e.g. "24h", "1h", "7d"
}

func (s *Server) createTarget(w http.ResponseWriter, r *http.Request) {
	var req createTargetReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid JSON body")
		return
	}
	imgID, err := uuid.Parse(strings.TrimSpace(req.ImageID))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid image_id")
		return
	}
	ok, err := db.ImageIsActive(r.Context(), s.Pool, imgID)
	if err != nil || !ok {
		writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "image not found")
		return
	}
	exists, err := db.TargetExists(r.Context(), s.Pool, imgID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "check failed")
		return
	}
	if exists {
		writeAPIError(w, http.StatusConflict, "ALREADY_EXISTS", "this image is already monitored")
		return
	}
	freq := strings.TrimSpace(req.ScanFrequency)
	if freq == "" {
		freq = "24h"
	}
	id, err := db.CreateTarget(r.Context(), s.Pool, imgID, freq)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "create failed")
		return
	}
	tr, err := db.GetTargetByID(r.Context(), s.Pool, id)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "load failed")
		return
	}
	writeEnvelope(w, http.StatusCreated, targetToResp(tr), nil)
}

func (s *Server) listTargets(w http.ResponseWriter, r *http.Request) {
	targets, err := db.ListTargets(r.Context(), s.Pool, r.URL.Query().Get("severity_min"))
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "list failed")
		return
	}
	out := make([]map[string]any, 0, len(targets))
	for _, tr := range targets {
		out = append(out, targetToResp(tr))
	}
	writeEnvelope(w, http.StatusOK, out, nil)
}

func (s *Server) deleteTarget(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid id")
		return
	}
	if err := db.SoftDeleteTarget(r.Context(), s.Pool, id); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "delete failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) updateTarget(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid id")
		return
	}
	var req createTargetReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid JSON body")
		return
	}
	freq := strings.TrimSpace(req.ScanFrequency)
	if freq == "" {
		freq = "24h"
	}
	if err := db.UpdateTarget(r.Context(), s.Pool, id, freq); err != nil {
		if err == pgx.ErrNoRows {
			writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "target not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
		return
	}
	tr, err := db.GetTargetByID(r.Context(), s.Pool, id)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "load failed")
		return
	}
	writeEnvelope(w, http.StatusOK, targetToResp(tr), nil)
}

func (s *Server) triggerTargetScan(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid id")
		return
	}
	tr, err := db.GetTargetByID(r.Context(), s.Pool, id)
	if err != nil {
		if err == pgx.ErrNoRows {
			writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "target not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "load failed")
		return
	}
	d, err := db.GetImageByID(r.Context(), s.Pool, tr.ImageID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "image load failed")
		return
	}
	scanID, err := db.InsertManualScan(r.Context(), s.Pool, tr.ImageID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "scan create failed")
		return
	}
	ref := imageref.BuildImagePullRef(d.RegistryURL, d.Repository, d.Tag)
	regRow, err := db.GetRegistryByID(r.Context(), s.Pool, d.RegistryID)
	regCreds := (*scanqueue.RegistryCredentials)(nil)
	if err == nil {
		regCreds = extractRegistryCredentials(&regRow)
	}
	if err := scanqueue.Enqueue(r.Context(), s.Redis, s.queueKey(), scanID, ref, regCreds); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "enqueue failed")
		return
	}
	_ = db.UpdateTargetLatestScan(r.Context(), s.Pool, tr.ID, scanID, "pending")
	detail, err := db.GetScanDetail(r.Context(), s.Pool, scanID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "scan load failed")
		return
	}
	writeEnvelope(w, http.StatusAccepted, scanDetailToResp(detail), nil)
}

func targetToResp(tr db.Target) map[string]any {
	m := map[string]any{
		"id":              tr.ID.String(),
		"image_id":        tr.ImageID.String(),
		"scan_frequency":  tr.ScanFrequency,
		"created_at":      tr.CreatedAt.UTC().Format(timeRFC3339),
		"updated_at":      tr.UpdatedAt.UTC().Format(timeRFC3339),
		"repository":      tr.ImageRepository,
		"tag":             tr.ImageTag,
		"registry_url":    tr.RegistryURL,
		"registry_name":   tr.RegistryName,
	}
	if tr.LatestScanID != nil {
		m["latest_scan_id"] = tr.LatestScanID.String()
	}
	if tr.LatestScanStatus != nil {
		m["latest_scan_status"] = *tr.LatestScanStatus
	}
	return m
}
