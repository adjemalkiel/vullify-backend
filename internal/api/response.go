package api

import (
	"encoding/json"
	"net/http"
)

// Meta is pagination metadata for list responses.
type Meta struct {
	Page    int   `json:"page"`
	PerPage int   `json:"per_page"`
	Total   int64 `json:"total"`
}

// envelope is the standard JSON response shape.
type envelope struct {
	Data any   `json:"data"`
	Meta *Meta `json:"meta,omitempty"`
}

// errBody is the standard error response shape.
type errBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeEnvelope(w http.ResponseWriter, status int, data any, meta *Meta) {
	writeJSON(w, status, envelope{Data: data, Meta: meta})
}

func writeAPIError(w http.ResponseWriter, status int, code, msg string) {
	var e errBody
	e.Error.Code = code
	e.Error.Message = msg
	writeJSON(w, status, e)
}
