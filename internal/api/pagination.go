package api

import (
	"net/http"
	"strconv"
)

func parsePagination(r *http.Request) (page, perPage, offset int) {
	page = 1
	perPage = 20
	if v := r.URL.Query().Get("page"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			page = p
		}
	}
	if v := r.URL.Query().Get("per_page"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			perPage = p
		}
	}
	if perPage > 100 {
		perPage = 100
	}
	offset = (page - 1) * perPage
	return page, perPage, offset
}
