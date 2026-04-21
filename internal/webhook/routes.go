package webhook

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// Routes mounts POST /dockerhub, /github, /gitlab with auth middleware and body limits.
func Routes(pool *pgxpool.Pool, rdb *redis.Client) http.Handler {
	h := &Handler{Pool: pool, Redis: rdb}
	r := chi.NewRouter()
	const maxBody = 2 << 20 // 2 MiB
	r.Use(MaxBodyBytes(maxBody))
	r.With(DockerHubAuth(pool)).Post("/dockerhub", h.DockerHub)
	r.With(GitHubAuth(pool)).Post("/github", h.GitHub)
	r.With(GitLabAuth(pool)).Post("/gitlab", h.GitLab)
	return r
}
