package api

import "net/http"

// managedReadOnlyRequest permits read-only history/chart queries using POST bodies.
func managedReadOnlyRequest(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		return true
	case http.MethodPost:
		switch r.URL.Path {
		case "/api/v1/netquery/query",
			"/api/v1/netquery/query/batch",
			"/api/v1/netquery/charts/connection-active",
			"/api/v1/netquery/charts/bandwidth":
			return true
		}
	}
	return false
}
