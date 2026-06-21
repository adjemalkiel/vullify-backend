package webhook

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"vullify/internal/db"
	"vullify/internal/imageref"
	"vullify/internal/scanqueue"
)

// Handler processes inbound registry webhooks (async after 200 OK).
type Handler struct {
	Pool     *pgxpool.Pool
	Redis    *redis.Client
	QueueKey string
	Log      *slog.Logger
}

func queueKey(h *Handler) string {
	if h.QueueKey != "" {
		return h.QueueKey
	}
	if k := os.Getenv("SCAN_QUEUE_KEY"); k != "" {
		return k
	}
	return scanqueue.DefaultKey
}

// DockerHub handles POST /webhooks/dockerhub (after DockerHubAuth middleware).
func (h *Handler) DockerHub(w http.ResponseWriter, r *http.Request) {
	reg, ok := registryFromContext(r.Context())
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	repoPath, tag, err := ParseDockerHubPush(body)
	if err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}
	h.respondOK(w)
	h.processAsync(reg, "dockerhub", "push", body, repoPath, tag)
}

// GitHub handles POST /webhooks/github for GHCR (after GitHubAuth middleware).
func (h *Handler) GitHub(w http.ResponseWriter, r *http.Request) {
	reg, ok := registryFromContext(r.Context())
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	repoPath, tag, err := ParseGitHubContainer(body)
	if err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}
	eventType := r.Header.Get("X-GitHub-Event")
	if eventType == "" {
		eventType = "package"
	}
	h.respondOK(w)
	h.processAsync(reg, "github", eventType, body, repoPath, tag)
}

// GitLab handles POST /webhooks/gitlab (after GitLabAuth middleware).
func (h *Handler) GitLab(w http.ResponseWriter, r *http.Request) {
	reg, ok := registryFromContext(r.Context())
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	repoPath, tag, err := ParseGitLabContainer(body)
	if err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}
	eventType := r.Header.Get("X-Gitlab-Event")
	if eventType == "" {
		if et := extractStringField(body, "event_type"); et != "" {
			eventType = et
		} else {
			eventType = "unknown"
		}
	}
	h.respondOK(w)
	h.processAsync(reg, "gitlab", eventType, body, repoPath, tag)
}

func extractStringField(body []byte, key string) string {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func (h *Handler) respondOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func (h *Handler) processAsync(reg db.RegistryRow, source, eventType string, body []byte, repository, tag string) {
	log := h.Log
	if log == nil {
		log = slog.Default()
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		payload := json.RawMessage(body)
		eventID, err := db.InsertWebhookEvent(ctx, h.Pool, source, eventType, payload)
		if err != nil {
			log.Error("webhook: insert event", "source", source, "err", err)
			return
		}
		imgID, err := db.UpsertImage(ctx, h.Pool, reg.ID, repository, tag)
		if err != nil {
			log.Error("webhook: upsert image", "event_id", eventID, "err", err)
			return
		}
		busy, err := db.ImageHasPendingOrRunningScan(ctx, h.Pool, imgID)
		if err != nil {
			log.Error("webhook: scan check", "event_id", eventID, "err", err)
			return
		}
		if busy {
			_ = db.MarkWebhookEventProcessed(ctx, h.Pool, eventID)
			log.Info("webhook: skipped enqueue (scan already pending/running)", "image_id", imgID)
			return
		}
		scanID, err := db.InsertWebhookScan(ctx, h.Pool, imgID)
		if err != nil {
			log.Error("webhook: insert scan", "event_id", eventID, "err", err)
			return
		}
		ref := imageref.BuildImagePullRef(reg.URL, repository, tag)
		if err := scanqueue.Enqueue(ctx, h.Redis, queueKey(h), scanID, ref, scanqueue.CredentialsFromRegistryJSON(reg.Type, reg.Credentials)); err != nil {
			log.Error("webhook: enqueue", "scan_id", scanID, "err", err)
			return
		}
		if err := db.MarkWebhookEventProcessed(ctx, h.Pool, eventID); err != nil {
			log.Warn("webhook: mark processed", "event_id", eventID, "err", err)
		}
		log.Info("webhook: scan enqueued", "source", source, "scan_id", scanID, "image_id", imgID)
	}()
}
