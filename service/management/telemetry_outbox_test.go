package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

func outboxHistory(t testing.TB, count int) (*sqlite.Conn, time.Time) {
	t.Helper()
	conn, err := sqlite.OpenConn(":memory:", 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	for _, sql := range []string{
		"ATTACH DATABASE ':memory:' AS history",
		`CREATE TABLE history.connections (id TEXT, started TEXT, type TEXT, profile_name TEXT,
			domain TEXT, remote_ip TEXT, verdict INTEGER, bytes_sent INTEGER, bytes_received INTEGER, internal INTEGER)`,
	} {
		if err := sqlitex.ExecuteTransient(conn, sql, nil); err != nil {
			t.Fatal(err)
		}
	}
	hour := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	for i := 0; i < count; i++ {
		if err := sqlitex.ExecuteTransient(conn,
			`INSERT INTO history.connections VALUES (?,?,'ip','Browser',?,'1.2.3.4',2,10,20,0)`,
			&sqlitex.ExecOptions{Args: []any{fmt.Sprint(i), hour.Format(sqliteTime), fmt.Sprintf("host-%04d.example", i)}}); err != nil {
			t.Fatal(err)
		}
	}
	return conn, hour
}

func outboxClient(t *testing.T, conn *sqlite.Conn, server *httptest.Server, hour time.Time) (*Client, Config) {
	t.Helper()
	dir := t.TempDir()
	for name, value := range map[string]any{
		stateFile:  State{DeviceID: "device-a", Credential: "credential"},
		cursorFile: telemetryCursor{DeviceID: "device-a", NextHour: hour},
	} {
		if err := writePrivateJSON(filepath.Join(dir, name), value); err != nil {
			t.Fatal(err)
		}
	}
	client := New(dir, sqliteTestStore{conn})
	client.httpClient = server.Client()
	return client, Config{ServerURL: server.URL}
}

// A partially accepted hour must survive process restart and local retention
// cleanup. Requerying pages changes the meaning of already deduplicated IDs.
func TestTelemetryRetryKeepsFrozenPagesAfterRestart(t *testing.T) {
	conn, hour := outboxHistory(t, 1001)
	var received []telemetryBatch
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch telemetryBatch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Error(err)
		}
		received = append(received, batch)
		if len(received) == 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)
	client, config := outboxClient(t, conn, server, hour)
	if err := client.flushTelemetry(context.Background(), config); err == nil {
		t.Fatal("server failure must leave the hour pending")
	}
	if len(received) != 2 || len(received[0].Destinations) != 1000 || len(received[1].Destinations) != 1 {
		t.Fatalf("expected two compact pages, got %d", len(received))
	}
	if err := sqlitex.ExecuteTransient(conn, "DROP TABLE history.connections", nil); err != nil {
		t.Fatal(err)
	}
	restarted := New(client.dataDir, sqliteTestStore{conn})
	restarted.httpClient = server.Client()
	if err := restarted.flushTelemetry(context.Background(), config); err != nil {
		t.Fatalf("retry must use durable summaries after history cleanup: %v", err)
	}
	if len(received) != 4 || !reflect.DeepEqual(received[0], received[2]) || !reflect.DeepEqual(received[1], received[3]) {
		t.Fatal("a retried batch changed contents or was lost")
	}
	data, err := os.ReadFile(filepath.Join(client.dataDir, cursorFile))
	if err != nil {
		t.Fatal(err)
	}
	var cursor telemetryCursor
	if json.Unmarshal(data, &cursor) != nil || !cursor.NextHour.Equal(hour.Add(time.Hour)) {
		t.Fatal("cursor did not advance exactly one acknowledged hour")
	}
}

func TestTelemetryCursorFailureRetainsAcknowledgedSummary(t *testing.T) {
	conn, hour := outboxHistory(t, 2)
	var received []telemetryBatch
	var cursorPath string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch telemetryBatch
		_ = json.NewDecoder(r.Body).Decode(&batch)
		received = append(received, batch)
		if len(received) == 1 {
			if err := os.Remove(cursorPath); err != nil {
				t.Error(err)
			}
			if err := os.Mkdir(cursorPath, 0700); err != nil {
				t.Error(err)
			}
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)
	client, config := outboxClient(t, conn, server, hour)
	cursorPath = filepath.Join(client.dataDir, cursorFile)
	if err := client.flushTelemetry(context.Background(), config); err == nil {
		t.Fatal("cursor persistence failure must be reported")
	}
	if err := sqlitex.ExecuteTransient(conn, "DROP TABLE history.connections", nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cursorPath); err != nil {
		t.Fatal(err)
	}
	if err := client.flushTelemetry(context.Background(), config); err != nil {
		t.Fatalf("accepted summary must remain retryable until cursor commits: %v", err)
	}
	if len(received) != 2 || !reflect.DeepEqual(received[0], received[1]) {
		t.Fatal("acknowledged summary was changed before its cursor committed")
	}
}

func TestTelemetryOutboxFailurePreventsUpload(t *testing.T) {
	conn, hour := outboxHistory(t, 2)
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)
	client, config := outboxClient(t, conn, server, hour)
	path := filepath.Join(client.dataDir, "management-telemetry-outbox.jsonl")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := client.flushTelemetry(context.Background(), config); err == nil || requests != 0 {
		t.Fatal("must durably stage summaries before any upload")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := client.flushTelemetry(context.Background(), config); err != nil || requests != 1 {
		t.Fatalf("queue failure should be recoverable without losing the hour: %v", err)
	}
}

func TestTelemetryDamagedOutboxDoesNotUploadOrAdvance(t *testing.T) {
	for _, damage := range []string{"truncated", "changed-count"} {
		t.Run(damage, func(t *testing.T) {
			conn, hour := outboxHistory(t, 2)
			requests := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			t.Cleanup(server.Close)
			client, config := outboxClient(t, conn, server, hour)
			if err := client.flushTelemetry(context.Background(), config); err == nil {
				t.Fatal("expected upload failure")
			}
			path := filepath.Join(client.dataDir, "management-telemetry-outbox.jsonl")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(data, []byte("credential")) || bytes.Contains(data, []byte("remote_ip")) {
				t.Fatal("outbox must contain compact summaries, not credentials or raw records")
			}
			if runtime.GOOS != "windows" {
				info, err := os.Stat(path)
				if err != nil || info.Mode().Perm() != 0600 {
					t.Fatal("outbox must have private file permissions")
				}
			}
			if damage == "truncated" {
				data = data[:bytes.LastIndex(data[:len(data)-1], []byte{'\n'})+1]
			} else {
				data = bytes.Replace(data, []byte(`"allowed":2`), []byte(`"allowed":3`), 1)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := client.flushTelemetry(context.Background(), config); err == nil || requests != 1 {
				t.Fatal("damaged queue must be reported before any upload")
			}
			cursorData, err := os.ReadFile(filepath.Join(client.dataDir, cursorFile))
			if err != nil {
				t.Fatal(err)
			}
			var cursor telemetryCursor
			if json.Unmarshal(cursorData, &cursor) != nil || !cursor.NextHour.Equal(hour) {
				t.Fatal("damaged queue advanced the cursor")
			}
		})
	}
}

func TestTelemetryPendingOutboxRecoversOlderHourWithoutCursor(t *testing.T) {
	conn, _ := outboxHistory(t, 2)
	hour := time.Now().UTC().Truncate(time.Hour).Add(-3 * time.Hour)
	if err := sqlitex.ExecuteTransient(conn, "UPDATE history.connections SET started = ?", &sqlitex.ExecOptions{Args: []any{hour.Format(sqliteTime)}}); err != nil {
		t.Fatal(err)
	}
	var received []telemetryBatch
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch telemetryBatch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Error(err)
		}
		received = append(received, batch)
		if len(received) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)
	client, config := outboxClient(t, conn, server, hour)
	if err := client.flushTelemetry(context.Background(), config); err == nil {
		t.Fatal("expected initial failure")
	}
	if err := os.Remove(filepath.Join(client.dataDir, cursorFile)); err != nil {
		t.Fatal(err)
	}
	if err := sqlitex.ExecuteTransient(conn, "DELETE FROM history.connections", nil); err != nil {
		t.Fatal(err)
	}
	restarted := New(client.dataDir, sqliteTestStore{conn})
	restarted.httpClient = server.Client()
	if err := restarted.flushTelemetry(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if len(received) != 4 || !reflect.DeepEqual(received[0], received[1]) {
		t.Fatal("missing cursor silently skipped an older durable pending hour")
	}
}

func TestTelemetryNewEnrollmentDoesNotSendPreviousIdentityOutbox(t *testing.T) {
	conn, hour := outboxHistory(t, 2)
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var batch telemetryBatch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Error(err)
		}
		if r.Header.Get("Authorization") != "Bearer credential-b" || len(batch.Destinations) != 0 || len(batch.Hourly) != 1 || batch.Hourly[0].Allowed != 0 {
			t.Error("previous identity's pending telemetry crossed enrollment boundary")
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)
	client, config := outboxClient(t, conn, server, hour)
	if err := client.flushTelemetry(context.Background(), config); err == nil {
		t.Fatal("expected initial failure")
	}
	if err := writePrivateJSON(filepath.Join(client.dataDir, stateFile), State{DeviceID: "device-b", Credential: "credential-b"}); err != nil {
		t.Fatal(err)
	}
	if err := sqlitex.ExecuteTransient(conn, "DELETE FROM history.connections", nil); err != nil {
		t.Fatal(err)
	}
	if err := client.flushTelemetry(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("got %d requests", requests)
	}
}

func TestTelemetryCanceledWorkerStopsBeforeReadingHistory(t *testing.T) {
	conn, hour := outboxHistory(t, 2)
	dir := t.TempDir()
	if err := writePrivateJSON(filepath.Join(dir, stateFile), State{DeviceID: "device-a", Credential: "credential"}); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateJSON(filepath.Join(dir, cursorFile), telemetryCursor{DeviceID: "device-a", NextHour: hour}); err != nil {
		t.Fatal(err)
	}
	if err := sqlitex.ExecuteTransient(conn, "DROP TABLE history.connections", nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := New(dir, sqliteTestStore{conn})
	if err := client.flushTelemetry(ctx, Config{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled worker must stop before scanning or rebuilding its outbox: %v", err)
	}
}

func TestTelemetryCommittedCursorDoesNotReplayLeftoverOutbox(t *testing.T) {
	conn, _ := outboxHistory(t, 2)
	oldHour := time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	if err := sqlitex.ExecuteTransient(conn, "UPDATE history.connections SET started = ?", &sqlitex.ExecOptions{Args: []any{oldHour.Format(sqliteTime)}}); err != nil {
		t.Fatal(err)
	}
	var received []telemetryBatch
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch telemetryBatch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Error(err)
		}
		received = append(received, batch)
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)
	client, config := outboxClient(t, conn, server, oldHour)
	if _, err := client.prepareTelemetryOutbox(context.Background(), State{DeviceID: "device-a"}, oldHour); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash between committing the cursor and removing the old spool.
	if err := writePrivateJSON(filepath.Join(client.dataDir, cursorFile), telemetryCursor{DeviceID: "device-a", NextHour: oldHour.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := sqlitex.ExecuteTransient(conn, "UPDATE history.connections SET started = ?", &sqlitex.ExecOptions{Args: []any{oldHour.Add(time.Hour).Format(sqliteTime)}}); err != nil {
		t.Fatal(err)
	}
	if err := client.flushTelemetry(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if len(received) != 1 || len(received[0].Hourly) != 1 || received[0].Hourly[0].Hour != oldHour.Add(time.Hour).Format(time.RFC3339) || received[0].Hourly[0].Allowed != 2 {
		t.Fatal("leftover committed outbox was replayed or prevented the next hour")
	}
}

func BenchmarkTelemetryOutbox(b *testing.B) {
	// Deliberately high-cardinality: every connection has a different host.
	// Excludes fixture setup and HTTP; measures local summary staging only.
	conn, hour := outboxHistory(b, 5000)
	client := New(b.TempDir(), sqliteTestStore{conn})
	state := State{DeviceID: "benchmark"}
	path := filepath.Join(client.dataDir, "management-telemetry-outbox.jsonl")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.prepareTelemetryOutbox(context.Background(), state, hour); err != nil {
			b.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportMetric(float64(info.Size()), "bytes/outbox")
		if err := os.Remove(path); err != nil {
			b.Fatal(err)
		}
	}
}
