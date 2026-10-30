// Package api is lockhub's HTTP API, version 1.
//
// Locks reach it on the internal hub network; facades reach it on a host
// socket. Every route but /v1/hello is added by later versions.
package api

import (
	"encoding/json"
	"net/http"
)

// Version is the API version this hub speaks.
const Version = 1

// Hello is the answer to GET /v1/hello.
type Hello struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	API     int    `json:"api"`
}

// Handler returns the hub's routes. version is the build version.
func Handler(version string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/hello", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, Hello{Name: "lockhub", Version: version, API: Version})
	})
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
