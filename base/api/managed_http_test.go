package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/packettale/agents/base/config"
)

func TestManagedEndpointDeniesMutableHTTPAndKeepsHistoryQueries(t *testing.T) { //nolint:paralleltest
	config.SetLocalWritesLocked(true)
	defer config.SetLocalWritesLocked(false)

	router := mux.NewRouter()
	for _, path := range []string{
		"/api/v1/sync/profile/import", "/api/v1/control/pause",
		"/api/v1/netquery/history/clear", "/api/v1/netquery/query",
		"/api/v1/updates/from-url", "/api/v1/updates/apply",
		"/api/v1/enterprise/access-requests",
	} {
		router.Handle(path, WrapInAuthHandler(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}, PermitAnyone, PermitAnyone))
	}
	handler := &mainHandler{mux: router}
	for _, path := range []string{
		"/api/v1/sync/profile/import", "/api/v1/control/pause",
		"/api/v1/netquery/history/clear", "/api/v1/updates/from-url",
		"/api/v1/updates/apply",
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
		if response.Code != http.StatusForbidden {
			t.Errorf("POST %s: got %d, want 403", path, response.Code)
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/netquery/query", nil))
	if response.Code != http.StatusNoContent {
		t.Errorf("history query: got %d, want 204", response.Code)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/enterprise/access-requests", nil))
	if response.Code != http.StatusForbidden {
		t.Errorf("retired employee action: got %d, want 403", response.Code)
	}
}
