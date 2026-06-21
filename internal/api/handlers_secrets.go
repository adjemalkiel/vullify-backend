package api

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"vullify/internal/db"
)

func (s *Server) listSecrets(w http.ResponseWriter, r *http.Request) {
	scanID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid id")
		return
	}

	page, perPage, offset := parsePagination(r)
	severity := strings.ToLower(r.URL.Query().Get("severity"))

	rows, total, err := db.ListSecretsForScanPaginated(r.Context(), s.Pool, scanID, severity, offset, perPage)
	if err != nil {
		if err == pgx.ErrNoRows {
			writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "scan not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "list failed")
		return
	}

	out := make([]map[string]any, 0, len(rows))
	for _, sec := range rows {
		item := map[string]any{
			"rule_id":   sec.RuleID,
			"category":  sec.Category,
			"severity":  sec.Severity,
			"title":     sec.Title,
			"file_path": sec.FilePath,
		}
		if sec.MatchText != "" {
			item["match_text"] = sec.MatchText
		}
		if sec.StartLine > 0 || sec.EndLine > 0 {
			item["start_line"] = sec.StartLine
			item["end_line"] = sec.EndLine
		}
		if sec.LayerDigest != "" {
			item["layer_digest"] = sec.LayerDigest
		}
		out = append(out, item)
	}

	writeEnvelope(w, http.StatusOK, out, &Meta{Page: page, PerPage: perPage, Total: int64(total)})
}
