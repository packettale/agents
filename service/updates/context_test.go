package updates

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestForceUpdateContextCancelsStalledIntelligenceRequest(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()
	updater, err := New(&testInstance{}, "context test", Config{Name: "Context", Directory: t.TempDir(),
		DownloadDirectory: t.TempDir(), PurgeDirectory: t.TempDir(), IndexFile: "index.json"})
	if err != nil {
		t.Fatal(err)
	}
	// Bypass only constructor URL validation for the loopback test fixture.
	updater.cfg.IndexURLs = []string{server.URL}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- updater.ForceUpdateContext(ctx) }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected cancellation, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("operation did not respect cancellation")
	}
	if updater.isUpdateRunning.IsSet() {
		t.Fatal("cancelled update retained busy flag")
	}
}
