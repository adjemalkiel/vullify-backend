package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"vullify/internal/db"
)

func (s *Server) listPackages(w http.ResponseWriter, r *http.Request) {
	scanID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid id")
		return
	}

	page, perPage, offset := parsePagination(r)
	pkgType := r.URL.Query().Get("type")

	rows, total, err := db.ListPackagesForScanPaginated(r.Context(), s.Pool, scanID, pkgType, offset, perPage)
	if err != nil {
		if err == pgx.ErrNoRows {
			writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "scan not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "list failed")
		return
	}

	out := make([]map[string]any, 0, len(rows))
	for _, pkg := range rows {
		m := map[string]any{
			"name":    pkg.Name,
			"version": pkg.Version,
			"type":    pkg.Type,
		}
		if pkg.LayerDigest != "" {
			m["layer_digest"] = pkg.LayerDigest
		}
		if len(pkg.Licenses) > 0 {
			m["licenses"] = pkg.Licenses
		}
		if pkg.FilePath != "" {
			m["file_path"] = pkg.FilePath
		}
		out = append(out, m)
	}

	writeEnvelope(w, http.StatusOK, out, &Meta{Page: page, PerPage: perPage, Total: int64(total)})
}
