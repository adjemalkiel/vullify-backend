package webhook

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"vullify/internal/db"
	"vullify/internal/registry"
)

// MaxBodyBytes limits request body size (use before auth middleware that reads the body).
func MaxBodyBytes(n int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, n)
			next.ServeHTTP(w, r)
		})
	}
}

func dockerHubBearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) >= 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	if t := r.Header.Get("X-Webhook-Token"); t != "" {
		return t
	}
	return r.Header.Get("X-Hub-Signature")
}

// DockerHubAuth validates the shared webhook secret (Bearer / X-Webhook-Token) against registries.credentials.webhook_secret.
func DockerHubAuth(pool *pgxpool.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read body", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))

			tok := dockerHubBearerToken(r)
			if tok == "" {
				http.Error(w, "missing webhook token", http.StatusUnauthorized)
				return
			}

			regs, err := db.ListRegistriesByType(r.Context(), pool, registry.TypeDockerHub)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			for _, row := range regs {
				var c registry.DockerHubCredentials
				if err := json.Unmarshal(row.Credentials, &c); err != nil {
					continue
				}
				if c.WebhookSecret == "" {
					continue
				}
				if len(tok) != len(c.WebhookSecret) {
					continue
				}
				if subtle.ConstantTimeCompare([]byte(tok), []byte(c.WebhookSecret)) == 1 {
					next.ServeHTTP(w, r.WithContext(withRegistry(r.Context(), row)))
					return
				}
			}
			http.Error(w, "invalid webhook token", http.StatusUnauthorized)
		})
	}
}

// GitHubAuth validates X-Hub-Signature-256 using registries.credentials.webhook_secret for ghcr registries.
func GitHubAuth(pool *pgxpool.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read body", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))

			sig256 := r.Header.Get("X-Hub-Signature-256")
			sig1 := r.Header.Get("X-Hub-Signature")
			if sig256 == "" && sig1 == "" {
				http.Error(w, "missing signature", http.StatusUnauthorized)
				return
			}

			regs, err := db.ListRegistriesByType(r.Context(), pool, registry.TypeGHCR)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			for _, row := range regs {
				var c registry.GHCRCredentials
				if err := json.Unmarshal(row.Credentials, &c); err != nil {
					continue
				}
				if c.WebhookSecret == "" {
					continue
				}
				if VerifyGitHubSignature256(body, sig256, c.WebhookSecret) ||
					VerifyGitHubSignature1(body, sig1, c.WebhookSecret) {
					next.ServeHTTP(w, r.WithContext(withRegistry(r.Context(), row)))
					return
				}
			}
			http.Error(w, "invalid signature", http.StatusUnauthorized)
		})
	}
}

// GitLabAuth validates X-Gitlab-Token against registries.credentials.webhook_secret.
func GitLabAuth(pool *pgxpool.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read body", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))

			tok := r.Header.Get("X-Gitlab-Token")
			if tok == "" {
				http.Error(w, "missing X-Gitlab-Token", http.StatusUnauthorized)
				return
			}

			regs, err := db.ListRegistriesByType(r.Context(), pool, registry.TypeGitLab)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			for _, row := range regs {
				var c registry.GitLabCredentials
				if err := json.Unmarshal(row.Credentials, &c); err != nil {
					continue
				}
				if c.WebhookSecret == "" {
					continue
				}
				if len(tok) != len(c.WebhookSecret) {
					continue
				}
				if subtle.ConstantTimeCompare([]byte(tok), []byte(c.WebhookSecret)) == 1 {
					next.ServeHTTP(w, r.WithContext(withRegistry(r.Context(), row)))
					return
				}
			}
			http.Error(w, "invalid token", http.StatusUnauthorized)
		})
	}
}
