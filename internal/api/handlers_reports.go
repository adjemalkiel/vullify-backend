package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"vullify/internal/db"
)

type generateReportReq struct {
	ScanID   string `json:"scan_id"`
	TargetID string `json:"target_id"`
	Format   string `json:"format"` // "json" (default), "html"
}

func (s *Server) generateReport(w http.ResponseWriter, r *http.Request) {
	var req generateReportReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid JSON body")
		return
	}

	var scanID uuid.UUID
	var err error

	switch {
	case strings.TrimSpace(req.ScanID) != "":
		scanID, err = uuid.Parse(strings.TrimSpace(req.ScanID))
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid scan_id")
			return
		}
	case strings.TrimSpace(req.TargetID) != "":
		targetID, err2 := uuid.Parse(strings.TrimSpace(req.TargetID))
		if err2 != nil {
			writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid target_id")
			return
		}
		tr, err2 := db.GetTargetByID(r.Context(), s.Pool, targetID)
		if err2 != nil {
			writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "target not found")
			return
		}
		if tr.LatestScanID == nil {
			writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "no scan found for this target")
			return
		}
		scanID = *tr.LatestScanID
	default:
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "scan_id or target_id is required")
		return
	}

	detail, err := db.GetScanDetail(r.Context(), s.Pool, scanID)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "scan not found")
		return
	}

	format := strings.TrimSpace(req.Format)
	if format == "" {
		format = "json"
	}

	findings, _, err := db.ListFindingsForScan(r.Context(), s.Pool, scanID, "", "", "", 0, 10000)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "findings load failed")
		return
	}

	findingList := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		m := map[string]any{
			"vulnerability_id": f.VulnerabilityID,
			"package_name":     f.PackageName,
			"severity":         f.Severity,
		}
		if f.Title != nil {
			m["title"] = *f.Title
		}
		if f.InstalledVersion != nil {
			m["installed_version"] = *f.InstalledVersion
		}
		if f.FixedVersion != nil {
			m["fixed_version"] = *f.FixedVersion
		}
		findingList = append(findingList, m)
	}

	switch format {
	case "html":
		s.renderHTMLReport(w, detail, findingList)
		return
	case "json":
		report := map[string]any{
			"scan_id":         detail.ID.String(),
			"image":           detail.Repository + ":" + detail.Tag,
			"status":          detail.Status,
			"triggered_by":    detail.TriggeredBy,
			"started_at":      ptrTime(detail.StartedAt),
			"completed_at":    ptrTime(detail.CompletedAt),
			"trivy_version":   detail.TrivyVersion,
			"error_message":   detail.ErrorMessage,
			"severity_counts": detail.SeverityCount,
			"findings":        findingList,
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=vullify-report-"+scanID.String()+".json")
		w.WriteHeader(http.StatusOK)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
		return
	default:
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "unsupported format; use 'json' or 'html'")
		return
	}
}

func (s *Server) renderHTMLReport(w http.ResponseWriter, detail db.ScanDetail, findings []map[string]any) {
	severityClass := func(sev string) string {
		switch sev {
		case "critical":
			return "color:#ec4899"
		case "high":
			return "color:#ef4444"
		case "medium":
			return "color:#f59e0b"
		case "low":
			return "color:#22c55e"
		default:
			return "color:#9ca3af"
		}
	}

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Vullify Scan Report</title>
<style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:2rem}
h1{color:#fff;font-size:1.5rem}h2{color:#94a3b8;font-size:1rem;text-transform:uppercase;letter-spacing:.05em}
.card{background:#1e293b;border:1px solid #334155;border-radius:.75rem;padding:1.5rem;margin-bottom:1rem}
.badge{display:inline-block;padding:.125rem .5rem;border-radius:.25rem;font-size:.75rem;font-weight:600}
table{width:100%;border-collapse:collapse}th{text-align:left;color:#94a3b8;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;padding:.5rem .75rem;border-bottom:1px solid #334155}
td{padding:.5rem .75rem;border-bottom:1px solid #1e293b;font-size:.875rem}
tr:hover{background:rgba(51,65,85,.3)}</style></head><body>`)
	b.WriteString(`<h1>Vullify Scan Report</h1>`)

	b.WriteString(`<div class="card">`)
	b.WriteString(`<h2>Overview</h2>`)
	b.WriteString(`<table><tr><td style="width:140px;color:#94a3b8">Image</td><td>` + detail.Repository + ":" + detail.Tag + `</td></tr>`)
	b.WriteString(fmt.Sprintf(`<tr><td style="color:#94a3b8">Scan ID</td><td style="font-family:monospace">%s</td></tr>`, detail.ID.String()))
	b.WriteString(fmt.Sprintf(`<tr><td style="color:#94a3b8">Status</td><td>%s</td></tr>`, detail.Status))
	if detail.StartedAt != nil {
		b.WriteString(fmt.Sprintf(`<tr><td style="color:#94a3b8">Started</td><td>%s</td></tr>`, detail.StartedAt.Format("2006-01-02 15:04:05")))
	}
	if detail.CompletedAt != nil {
		b.WriteString(fmt.Sprintf(`<tr><td style="color:#94a3b8">Completed</td><td>%s</td></tr>`, detail.CompletedAt.Format("2006-01-02 15:04:05")))
	}
	if detail.TrivyVersion != nil && *detail.TrivyVersion != "" {
		b.WriteString(fmt.Sprintf(`<tr><td style="color:#94a3b8">Trivy</td><td>%s</td></tr>`, *detail.TrivyVersion))
	}
	if detail.ErrorMessage != nil {
		b.WriteString(`<tr><td style="color:#94a3b8">Error</td><td style="color:#ef4444">` + *detail.ErrorMessage + `</td></tr>`)
	}
	b.WriteString(`</table></div>`)

	if len(detail.SeverityCount) > 0 {
		b.WriteString(`<div class="card"><h2>Severity Breakdown</h2>`)
		order := []string{"critical", "high", "medium", "low", "unknown"}
		for _, sev := range order {
			if n, ok := detail.SeverityCount[sev]; ok && n > 0 {
				b.WriteString(fmt.Sprintf(`<span class="badge" style="%s">%s: %d</span>&nbsp;`, severityClass(sev), sev, n))
			}
		}
		b.WriteString(`</div>`)
	}

	b.WriteString(`<div class="card"><h2>Findings (` + fmt.Sprintf("%d", len(findings)) + `)</h2>`)
	b.WriteString(`<table><thead><tr><th>CVE ID</th><th>Package</th><th>Severity</th><th>Installed</th><th>Fixed</th><th>Title</th></tr></thead><tbody>`)
	for _, f := range findings {
		sev, _ := f["severity"].(string)
		cve, _ := f["vulnerability_id"].(string)
		pkg, _ := f["package_name"].(string)
		inst, _ := f["installed_version"].(string)
		fixed, _ := f["fixed_version"].(string)
		title, _ := f["title"].(string)
		if title == "" {
			title = "—"
		}
		fixedCell := fixed
		if fixedCell == "" {
			fixedCell = `<span style="color:#6b7280">—</span>`
		} else {
			fixedCell = `<span style="color:#22c55e">` + fixedCell + `</span>`
		}
		b.WriteString(fmt.Sprintf(`<tr><td style="font-family:monospace;color:#22d3ee">%s</td><td>%s</td><td style="%s">%s</td><td>%s</td><td>%s</td><td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">%s</td></tr>`,
			cve, pkg, severityClass(sev), sev, inst, fixedCell, title))
	}
	b.WriteString(`</tbody></table></div>`)
	b.WriteString(`</body></html>`)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}
