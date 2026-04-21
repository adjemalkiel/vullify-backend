package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"vullify/internal/webhook"
)

// NewHandler builds the full API with chi router and middleware.
func NewHandler(pool *pgxpool.Pool, rdb *redis.Client) http.Handler {
	s := &Server{Pool: pool, Redis: rdb}
	return routes(s)
}

func routes(s *Server) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/healthz", healthz)

	r.Mount("/webhooks", webhook.Routes(s.Pool, s.Redis))

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(jsonContentType)

		r.Route("/registries", func(r chi.Router) {
			r.Post("/", s.createRegistry)
			r.Get("/", s.listRegistries)
			r.Route("/{id}", func(r chi.Router) {
				r.Get("/", s.getRegistry)
				r.Put("/", s.updateRegistry)
				r.Delete("/", s.deleteRegistry)
				r.Post("/sync", s.syncRegistry)
			})
		})

		r.Route("/images", func(r chi.Router) {
			r.Get("/", s.listImages)
			r.Get("/{id}", s.getImage)
		})

		r.Route("/scans", func(r chi.Router) {
			r.Post("/", s.createScan)
			r.Route("/{id}", func(r chi.Router) {
				r.Get("/", s.getScan)
				r.Get("/findings", s.listScanFindings)
				r.Get("/sbom", s.getScanSBOM)
			})
		})

		r.Get("/findings/{id}", s.getFinding)

		r.Get("/dashboard/summary", s.dashboardSummary)
		r.Get("/reports/vulnerability", s.vulnerabilityReport)
	})

	return r
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}
