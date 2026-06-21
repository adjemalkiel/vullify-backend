package api

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"vullify/internal/db"
)

func (s *Server) listMisconfigurations(w http.ResponseWriter, r *http.Request) {
	scanID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid id")
		return
	}

	page, perPage, offset := parsePagination(r)
	severity := strings.ToLower(r.URL.Query().Get("severity"))

	rows, total, err := db.ListMisconfigsForScanPaginated(r.Context(), s.Pool, scanID, severity, offset, perPage)
	if err != nil {
		if err == pgx.ErrNoRows {
			writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "scan not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "list failed")
		return
	}

	out := make([]map[string]any, 0, len(rows))
	for _, m := range rows {
		item := map[string]any{
			"type":      m.Type,
			"check_id":  m.CheckID,
			"title":     m.Title,
			"severity":  m.Severity,
			"file_path": m.FilePath,
		}
		if m.Description != "" {
			item["description"] = m.Description
		}
		if m.Resolution != "" {
			item["resolution"] = m.Resolution
		}
		if m.StartLine > 0 || m.EndLine > 0 {
			item["start_line"] = m.StartLine
			item["end_line"] = m.EndLine
		}
		out = append(out, item)
	}

	writeEnvelope(w, http.StatusOK, out, &Meta{Page: page, PerPage: perPage, Total: int64(total)})
}
