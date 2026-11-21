package management

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/packettale/agents/service/netquery/orm"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

type compactTestStore struct {
	pending  *CompactDelivery
	inactive bool
}

func (s *compactTestStore) Execute(context.Context, string, ...orm.QueryOption) error {
	return errors.New("must not scan raw history after compact capture is active")
}
func (s *compactTestStore) ConfigureCompactSummaries(context.Context, string, bool) (bool, error) {
	return !s.inactive, nil
}
func (s *compactTestStore) NextCompactSummary(context.Context, string) (*CompactDelivery, error) {
	return s.pending, nil
}
func (s *compactTestStore) AcknowledgeCompactSummary(_ context.Context, _ string, id string, sequence int64) error {
	if s.pending == nil || id != s.pending.StreamID || sequence != s.pending.Sequence {
		return errors.New("incorrect acknowledgment")
	}
	s.pending = nil
	return nil
}

func TestCompactClientRetriesUntilMatchingAcknowledgmentWithoutHistoryQueries(t *testing.T) {
	stream := "e1e20a0d-46e6-4449-9c44-cd9cb954a36f"
	batch := CompactBatch{StreamID: stream, Sequence: 1, StartedAt: time.Now().UTC().Format(time.RFC3339), Hourly: []CompactHour{}, Destinations: []CompactDestination{{Day: time.Now().UTC().Format("2006-01-02"), ProfileID: "local/browser", App: "Browser", Host: "example.test", Allowed: 1}}}
	body, err := MarshalCompactBatch(batch)
	if err != nil {
		t.Fatal(err)
	}
	store := &compactTestStore{pending: &CompactDelivery{StreamID: stream, Sequence: 1, Body: body}}
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/api/v1/device/summaries/" || r.Header.Get("Authorization") != "Bearer credential" {
			t.Error("incorrect compact request route or identity")
		}
		var got CompactBatch
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
		}
		if got.Sequence != 1 || got.StreamID != stream || len(got.Destinations) != 1 || got.Destinations[0].Allowed != 1 {
			t.Error("immutable compact payload changed")
		}
		if requests == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		sequence := int64(1)
		if requests == 2 {
			sequence = 2
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{"accepted": true, "stream_id": stream, "sequence": sequence})
	}))
	defer server.Close()
	dir := t.TempDir()
	client := New(dir, store)
	client.httpClient = server.Client()
	if err := writePrivateJSON(filepath.Join(dir, stateFile), State{DeviceID: "endpoint-a", Credential: "credential"}); err != nil {
		t.Fatal(err)
	}
	config := Config{ServerURL: server.URL}
	for i := 0; i < 2; i++ {
		if err := client.flushTelemetry(context.Background(), config); err == nil || store.pending == nil {
			t.Fatal("failed or mismatched acknowledgment lost queued telemetry")
		}
	}
	if err := client.flushTelemetry(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if requests != 3 || store.pending != nil {
		t.Fatal("matching acknowledgment did not complete the delivery")
	}
}

func TestCompactInactiveEnrollmentClearsDeliveryCadence(t *testing.T) {
	dir := t.TempDir()
	client := New(dir, &compactTestStore{inactive: true})
	client.compactSummaryActive.Store(true)
	if err := writePrivateJSON(filepath.Join(dir, stateFile), State{DeviceID: "endpoint-b", Credential: "credential-b"}); err != nil {
		t.Fatal(err)
	}
	_ = client.flushTelemetry(context.Background(), Config{})
	if client.compactSummaryActive.Load() {
		t.Fatal("inactive enrollment kept the previous compact delivery cadence")
	}
}
