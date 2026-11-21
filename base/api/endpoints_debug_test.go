package api

import (
	"github.com/packettale/agents/base/log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type readinessTestInstance struct {
	testInstance
	ready bool
}

func (stub *readinessTestInstance) Ready() bool { return stub.ready }

func TestReadinessEndpointTracksServiceState(t *testing.T) {
	original := module.instance
	stub := &readinessTestInstance{}
	module.instance = stub
	t.Cleanup(func() { module.instance = original })
	handler := &mainHandler{mux: mainMux}

	for _, state := range []struct {
		name   string
		ready  bool
		status int
		body   string
	}{
		{"starting", false, http.StatusTooEarly, "packettale is not ready"},
		{"running", true, http.StatusOK, "packettale is ready."},
		{"stopped", false, http.StatusTooEarly, "packettale is not ready"},
	} {
		t.Run(state.name, func(t *testing.T) {
			stub.ready = state.ready
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, apiV1Path+"ready", nil))
			if response.Code != state.status {
				t.Errorf("status = %d, want %d; body: %s", response.Code, state.status, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), state.body) {
				t.Errorf("body = %q, want %q", response.Body.String(), state.body)
			}
		})
	}
}

// Diagnostics can contain logs and process state. Reject ordinary local clients
// before invoking their handlers, including costly profiling operations.
func TestDiagnosticsRequireAdministrativeAuthentication(t *testing.T) {
	original := *testToken
	t.Cleanup(func() { *testToken = original })
	handler := &mainHandler{mux: mainMux}
	paths := []string{"debug/stack", "debug/stack/print", "debug/cpu?duration=invalid", "debug/heap", "debug/allocs", "debug/info"}
	for _, permission := range []Permission{PermitAnyone, PermitUser} {
		*testToken = AuthToken{Read: permission}
		for _, path := range paths {
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, httptest.NewRequest(method, apiV1Path+path, nil))
				if response.Code != http.StatusForbidden {
					t.Errorf("%s %s with %s: status %d, want 403", method, path, permission, response.Code)
				}
			}
		}
		for _, path := range []string{"ping", "ready"} {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, apiV1Path+path, nil))
			if response.Code != http.StatusOK {
				t.Errorf("health %s: status %d", path, response.Code)
			}
		}
	}
	*testToken = AuthToken{Read: PermitAdmin}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, apiV1Path+"debug/stack", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "goroutine profile:") {
		t.Errorf("authenticated diagnostics unavailable: status %d", response.Code)
	}
}

func TestPrintStackUsesServiceLogWithoutConsole(t *testing.T) {
	directory := t.TempDir()
	writer, err := log.NewFileWriter(directory)
	if err != nil {
		t.Fatal(err)
	}
	originalWriter, originalStderr := log.GlobalWriter, os.Stderr
	closed, err := os.Open(os.DevNull)
	if err != nil {
		writer.Close()
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		writer.Close()
		t.Fatal(err)
	}
	log.GlobalWriter, os.Stderr = writer, closed
	t.Cleanup(func() { log.GlobalWriter, os.Stderr = originalWriter, originalStderr; writer.Close() })
	if _, err := printStack(nil); err != nil {
		t.Fatalf("service without console: %v", err)
	}
	files, err := filepath.Glob(filepath.Join(directory, "*.log"))
	if err != nil || len(files) != 1 {
		t.Fatalf("service log files: %v, %v", files, err)
	}
	contents, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"===== PRINTING STACK =====", "goroutine profile:", "===== END OF STACK ====="} {
		if !strings.Contains(string(contents), expected) {
			t.Errorf("service log missing %q", expected)
		}
	}
}
