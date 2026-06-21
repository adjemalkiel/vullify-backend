package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"vullify/internal/db"
	"vullify/internal/imageref"
	"vullify/internal/scanqueue"
)

type adhocScanReq struct {
	ImageRef string `json:"image_ref"`
}

// parseImageRef extracts registry host, repository path, and tag from a Docker pull reference.
func parseImageRef(ref string) (host, repo, tag string) {
	ref = strings.TrimSpace(ref)

	// Extract tag
	if idx := strings.LastIndex(ref, ":"); idx != -1 {
		tag = ref[idx+1:]
		ref = ref[:idx]
	} else {
		tag = "latest"
	}

	// Extract host and repo
	if idx := strings.Index(ref, "/"); idx != -1 {
		first := ref[:idx]
		if strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost" {
			host = first
			repo = ref[idx+1:]
		} else {
			host = "docker.io"
			repo = ref
		}
	} else {
		host = "docker.io"
		repo = "library/" + ref
	}

	if host == "docker.io" && !strings.Contains(repo, "/") {
		repo = "library/" + repo
	}

	return host, repo, tag
}

func (s *Server) createAdhocScan(w http.ResponseWriter, r *http.Request) {
	var req adhocScanReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid JSON body")
		return
	}
	if strings.TrimSpace(req.ImageRef) == "" {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "image_ref is required")
		return
	}

	pullRef := strings.TrimSpace(req.ImageRef)

	// Try to find an existing image by pull reference.
	imgID, err := db.FindImageIDByPullRef(r.Context(), s.Pool, pullRef)
	if err != nil && err != pgx.ErrNoRows {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "lookup failed")
		return
	}

	if err == pgx.ErrNoRows {
		host, repo, tag := parseImageRef(pullRef)
		regID, regURL, err := findRegistryByHost(r.Context(), s.Pool, host)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR",
				"no registry configured for "+host+"; register one first")
			return
		}

		imgID, err = db.UpsertImage(r.Context(), s.Pool, regID, repo, tag)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create image")
			return
		}

		pullRef = imageref.BuildImagePullRef(regURL, repo, tag)
	}

	ok, err := db.ImageIsActive(r.Context(), s.Pool, imgID)
	if err != nil || !ok {
		writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "image not found or inactive")
		return
	}

	scanID, err := db.InsertManualScan(r.Context(), s.Pool, imgID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create scan")
		return
	}

	if err := scanqueue.Enqueue(r.Context(), s.Redis, s.queueKey(), scanID, pullRef); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to enqueue scan")
		return
	}

	detail, err := db.GetScanDetail(r.Context(), s.Pool, scanID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load scan")
		return
	}
	writeEnvelope(w, http.StatusAccepted, scanDetailToResp(detail), nil)
}

func findRegistryByHost(ctx context.Context, pool *pgxpool.Pool, host string) (uuid.UUID, string, error) {
	regs, _, err := db.ListRegistries(ctx, pool, 0, 100)
	if err != nil {
		return uuid.Nil, "", err
	}
	hostLower := strings.ToLower(host)
	for _, reg := range regs {
		if strings.Contains(strings.ToLower(reg.URL), hostLower) {
			return reg.ID, reg.URL, nil
		}
	}
	return uuid.Nil, "", pgx.ErrNoRows
}
