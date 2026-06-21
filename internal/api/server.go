package api

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"vullify/internal/db"
	"vullify/internal/registry"
	"vullify/internal/scanqueue"
)

// Server holds API dependencies.
type Server struct {
	Pool     *pgxpool.Pool
	Redis    *redis.Client
	QueueKey string
}

func (s *Server) queueKey() string {
	if k := os.Getenv("SCAN_QUEUE_KEY"); k != "" {
		return k
	}
	if s.QueueKey != "" {
		return s.QueueKey
	}
	return scanqueue.DefaultKey
}

func parseUUID(p string) (uuid.UUID, error) {
	return uuid.Parse(strings.TrimSpace(p))
}

func validRegistryType(t string) bool {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case registry.TypeDockerHub, registry.TypeGitLab, registry.TypeECR, registry.TypeGCR, registry.TypeGHCR,
		registry.TypeACR, registry.TypeGeneric:
		return true
	default:
		return false
	}
}

// --- registries ---

type registryCreateReq struct {
	Name        string          `json:"name"`
	Type        string          `json:"type"`
	URL         string          `json:"url"`
	Credentials json.RawMessage `json:"credentials"`
}

type registryUpdateReq struct {
	Name        *string          `json:"name"`
	Type        *string          `json:"type"`
	URL         *string          `json:"url"`
	Credentials *json.RawMessage `json:"credentials"`
}

type registryResp struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	URL         string    `json:"url"`
	CredentialsSet bool   `json:"credentials_set"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func registryToResp(r db.RegistryRow) registryResp {
	return registryResp{
		ID:             r.ID.String(),
		Name:           r.Name,
		Type:           r.Type,
		URL:            r.URL,
		CredentialsSet: len(r.Credentials) > 0 && string(r.Credentials) != "{}" && string(r.Credentials) != "null",
		CreatedAt:      r.CreatedAt,
		UpdatedAt:      r.UpdatedAt,
	}
}

func (s *Server) createRegistry(w http.ResponseWriter, r *http.Request) {
	var req registryCreateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid JSON body")
		return
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.URL) == "" {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "name and url are required")
		return
	}
	if req.Credentials == nil {
		req.Credentials = json.RawMessage(`{}`)
	}
	if !validRegistryType(req.Type) {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid registry type")
		return
	}
	conn, err := registry.NewConnector(req.Type, req.Credentials)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}
	if err := conn.TestConnection(r.Context()); err != nil {
		writeAPIError(w, http.StatusUnprocessableEntity, "REGISTRY_CONNECTION_FAILED", err.Error())
		return
	}
	id, err := db.InsertRegistry(r.Context(), s.Pool, req.Name, req.Type, req.URL, req.Credentials)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to save registry")
		return
	}
	row, err := db.GetRegistryByID(r.Context(), s.Pool, id)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load registry")
		return
	}
	writeEnvelope(w, http.StatusCreated, registryToResp(row), nil)
}

func (s *Server) listRegistries(w http.ResponseWriter, r *http.Request) {
	page, perPage, offset := parsePagination(r)
	rows, total, err := db.ListRegistries(r.Context(), s.Pool, offset, perPage)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "list failed")
		return
	}
	out := make([]registryResp, 0, len(rows))
	for _, row := range rows {
		out = append(out, registryToResp(row))
	}
	writeEnvelope(w, http.StatusOK, out, &Meta{Page: page, PerPage: perPage, Total: int64(total)})
}

func (s *Server) getRegistry(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid id")
		return
	}
	row, err := db.GetRegistryByID(r.Context(), s.Pool, id)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "registry not found")
		return
	}
	writeEnvelope(w, http.StatusOK, registryToResp(row), nil)
}

func (s *Server) updateRegistry(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid id")
		return
	}
	var req registryUpdateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid JSON body")
		return
	}
	cur, err := db.GetRegistryByID(r.Context(), s.Pool, id)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "registry not found")
		return
	}
	name := cur.Name
	typ := cur.Type
	url := cur.URL
	creds := cur.Credentials
	if req.Name != nil {
		name = *req.Name
	}
	if req.Type != nil {
		if !validRegistryType(*req.Type) {
			writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid registry type")
			return
		}
		typ = *req.Type
	}
	if req.URL != nil {
		url = *req.URL
	}
	if req.Credentials != nil {
		creds = *req.Credentials
	}
	conn, err := registry.NewConnector(typ, creds)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}
	if err := conn.TestConnection(r.Context()); err != nil {
		writeAPIError(w, http.StatusUnprocessableEntity, "REGISTRY_CONNECTION_FAILED", err.Error())
		return
	}
	if err := db.UpdateRegistry(r.Context(), s.Pool, id, name, typ, url, creds); err != nil {
		if err == pgx.ErrNoRows {
			writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "registry not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
		return
	}
	row, err := db.GetRegistryByID(r.Context(), s.Pool, id)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load registry")
		return
	}
	writeEnvelope(w, http.StatusOK, registryToResp(row), nil)
}

func (s *Server) deleteRegistry(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid id")
		return
	}
	if err := db.SoftDeleteRegistry(r.Context(), s.Pool, id); err != nil {
		if err == pgx.ErrNoRows {
			writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "registry not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "delete failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) syncRegistry(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid id")
		return
	}
	reg, err := db.GetRegistryByID(r.Context(), s.Pool, id)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "registry not found")
		return
	}
	conn, err := registry.NewConnector(reg.Type, reg.Credentials)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}
	repos, err := conn.ListRepositories(r.Context())
	if err != nil {
		writeAPIError(w, http.StatusBadGateway, "REGISTRY_SYNC_FAILED", err.Error())
		return
	}
	synced := 0
	for _, repoPath := range repos {
		tags, err := conn.ListTags(r.Context(), repoPath)
		if err != nil {
			continue
		}
		for _, tag := range tags {
			if _, err := db.UpsertImage(r.Context(), s.Pool, id, repoPath, tag); err == nil {
				synced++
			}
		}
	}
	writeEnvelope(w, http.StatusOK, map[string]any{"synced_images": synced, "repositories_seen": len(repos)}, nil)
}

// listRepositories returns all repositories in a registry.
func (s *Server) listRepositories(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid id")
		return
	}
	reg, err := db.GetRegistryByID(r.Context(), s.Pool, id)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "registry not found")
		return
	}
	conn, err := registry.NewConnector(reg.Type, reg.Credentials)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}
	repos, err := conn.ListRepositories(r.Context())
	if err != nil {
		writeAPIError(w, http.StatusBadGateway, "REGISTRY_LIST_FAILED", err.Error())
		return
	}
	if repos == nil {
		repos = []string{}
	}
	writeEnvelope(w, http.StatusOK, map[string]any{"repositories": repos}, nil)
}

// listTags returns all tags for a repository within a registry.
func (s *Server) listTags(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid id")
		return
	}
	repo := chi.URLParam(r, "*") // wildcard captures the full repository path including slashes
	if strings.TrimSpace(repo) == "" {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "repository path is required")
		return
	}
	reg, err := db.GetRegistryByID(r.Context(), s.Pool, id)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "registry not found")
		return
	}
	conn, err := registry.NewConnector(reg.Type, reg.Credentials)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}
	tags, err := conn.ListTags(r.Context(), repo)
	if err != nil {
		writeAPIError(w, http.StatusBadGateway, "REGISTRY_TAGS_FAILED", err.Error())
		return
	}
	if tags == nil {
		tags = []string{}
	}
	page, perPage, offset := parsePagination(r)
	if offset >= len(tags) {
		writeEnvelope(w, http.StatusOK, []string{}, &Meta{Page: page, PerPage: perPage, Total: int64(len(tags))})
		return
	}
	end := offset + perPage
	if end > len(tags) {
		end = len(tags)
	}
	writeEnvelope(w, http.StatusOK, tags[offset:end], &Meta{Page: page, PerPage: perPage, Total: int64(len(tags))})
}
