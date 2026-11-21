package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/packettale/agents/service/netquery/orm"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

type sqliteTestStore struct{ conn *sqlite.Conn }

func (s sqliteTestStore) Execute(ctx context.Context, sql string, opts ...orm.QueryOption) error {
	return orm.RunQuery(ctx, s.conn, sql, opts...)
}

func TestTelemetrySummarizesLocalHistoryAndAdvancesCursor(t *testing.T) {
	conn, err := sqlite.OpenConn(":memory:", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, sql := range []string{
		"ATTACH DATABASE ':memory:' AS history",
		`CREATE TABLE history.connections (id TEXT, started TEXT, type TEXT, profile_name TEXT,
			domain TEXT, remote_ip TEXT, remote_port INTEGER, worst_verdict INTEGER, verdict INTEGER,
			bytes_sent INTEGER, bytes_received INTEGER, internal INTEGER)`,
	} {
		if err := sqlitex.ExecuteTransient(conn, sql, nil); err != nil {
			t.Fatal(err)
		}
	}
	hour := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	for _, sql := range []string{
		`INSERT INTO history.connections VALUES ('a','` + hour.Format(sqliteTime) + `','ip','Browser','example.org','1.2.3.4',443,0,2,100,200,0)`,
		`INSERT INTO history.connections VALUES ('b','` + hour.Format(sqliteTime) + `','dns','Browser','blocked.test','',53,0,3,0,0,0)`,
	} {
		if err := sqlitex.ExecuteTransient(conn, sql, nil); err != nil {
			t.Fatal(err)
		}
	}
	var batches []telemetryBatch
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/device/telemetry/" || r.Header.Get("Authorization") != "Bearer credential" {
			t.Errorf("unexpected telemetry request")
		}
		var batch telemetryBatch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Error(err)
		}
		batches = append(batches, batch)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	dir := t.TempDir()
	client := New(dir, sqliteTestStore{conn})
	client.httpClient = server.Client()
	if err := writePrivateJSON(filepath.Join(dir, stateFile), State{DeviceID: "dev", Credential: "credential"}); err != nil {
		t.Fatal(err)
	}
	config := Config{ServerURL: server.URL}
	if err := client.flushTelemetry(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if len(batches) != 1 || len(batches[0].Hourly) != 1 || batches[0].Hourly[0].Allowed != 1 || batches[0].Hourly[0].Blocked != 1 || batches[0].Hourly[0].DNS != 1 || len(batches[0].Destinations) != 2 {
		t.Fatalf("unexpected compact telemetry: %+v", batches)
	}
	if err := client.flushTelemetry(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if len(batches) != 1 {
		t.Fatalf("sent duplicate completed hour: %d", len(batches))
	}
}

func TestEmptyDetailQueryEncodesAnArrayWithoutDisconnectingManagement(t *testing.T) {
	conn, err := sqlite.OpenConn(":memory:", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, query := range []string{"ATTACH DATABASE ':memory:' AS history", `CREATE TABLE history.connections(id TEXT,started TEXT,type TEXT,profile_name TEXT,profile TEXT,domain TEXT,remote_ip TEXT,remote_port INTEGER,verdict INTEGER,bytes_sent INTEGER,bytes_received INTEGER,internal INTEGER)`} {
		if err := sqlitex.ExecuteTransient(conn, query, nil); err != nil {
			t.Fatal(err)
		}
	}
	for _, column := range []string{"local_ip TEXT DEFAULT ''", "local_port INTEGER DEFAULT 0", "ip_protocol INTEGER DEFAULT 0", "direction TEXT DEFAULT ''", "path TEXT DEFAULT ''", "country TEXT DEFAULT ''", "asn INTEGER DEFAULT 0", "as_owner TEXT DEFAULT ''", "ended TEXT DEFAULT ''"} {
		if err := sqlitex.ExecuteTransient(conn, "ALTER TABLE history.connections ADD COLUMN "+column, nil); err != nil {
			t.Fatal(err)
		}
	}
	client := New(t.TempDir(), sqliteTestStore{conn})
	if err := sqlitex.ExecuteTransient(conn, "ALTER TABLE history.connections ADD COLUMN extra_data BLOB", nil); err != nil {
		t.Fatal(err)
	}
	response := client.queryDetail(context.Background(), []byte(`{"request_id":"empty","since":"2026-11-03 00:00:00","until":"2026-11-04 00:00:00","limit":100}`))
	if response.Error != "" {
		t.Fatal(response.Error)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	if records, ok := wire["records"].([]any); !ok || len(records) != 0 {
		t.Fatalf("empty history is not a valid list response: %s", encoded)
	}
}

func TestTelemetryUploadsEachHoursDestinationDelta(t *testing.T) {
	conn, err := sqlite.OpenConn(":memory:", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, sql := range []string{
		"ATTACH DATABASE ':memory:' AS history",
		`CREATE TABLE history.connections (id TEXT, started TEXT, type TEXT, profile_name TEXT,
			domain TEXT, remote_ip TEXT, remote_port INTEGER, verdict INTEGER,
			bytes_sent INTEGER, bytes_received INTEGER, internal INTEGER)`,
	} {
		if err := sqlitex.ExecuteTransient(conn, sql, nil); err != nil {
			t.Fatal(err)
		}
	}
	lastHour := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	firstHour := lastHour.Add(-time.Hour)
	for id, hour := range map[string]time.Time{"first": firstHour, "second": lastHour} {
		sql := `INSERT INTO history.connections VALUES ('` + id + `','` + hour.Format(sqliteTime) +
			`','ip','Browser','example.org','1.2.3.4',443,2,100,200,0)`
		if err := sqlitex.ExecuteTransient(conn, sql, nil); err != nil {
			t.Fatal(err)
		}
	}
	var batches []telemetryBatch
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch telemetryBatch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Error(err)
		}
		batches = append(batches, batch)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	dir := t.TempDir()
	client := New(dir, sqliteTestStore{conn})
	client.httpClient = server.Client()
	for name, value := range map[string]any{
		stateFile:  State{DeviceID: "dev", Credential: "credential"},
		cursorFile: telemetryCursor{DeviceID: "dev", NextHour: firstHour},
	} {
		if err := writePrivateJSON(filepath.Join(dir, name), value); err != nil {
			t.Fatal(err)
		}
	}
	if err := client.flushTelemetry(context.Background(), Config{ServerURL: server.URL}); err != nil {
		t.Fatal(err)
	}
	if len(batches) != 2 {
		t.Fatalf("sent %d batches, want 2", len(batches))
	}
	for _, batch := range batches {
		if batch.DestinationMode != "hourly_delta" || len(batch.Destinations) != 1 ||
			batch.Destinations[0].Allowed != 1 {
			t.Fatalf("not an hourly destination delta: %+v", batch)
		}
	}
}

func TestDetailQueryUsesStableCursorAndBlockedFilter(t *testing.T) {
	conn, err := sqlite.OpenConn(":memory:", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, sql := range []string{
		"ATTACH DATABASE ':memory:' AS history",
		`CREATE TABLE history.connections (id TEXT, started TEXT, type TEXT, profile_name TEXT, profile TEXT,
			domain TEXT, remote_ip TEXT, remote_port INTEGER, worst_verdict INTEGER, verdict INTEGER,
			bytes_sent INTEGER, bytes_received INTEGER, internal INTEGER)`,
		`INSERT INTO history.connections VALUES ('a','2026-11-01 01:00:00','ip','Browser','local/Browser123','allowed.test','1.2.3.4',443,0,2,100,200,0)`,
		`INSERT INTO history.connections VALUES ('b','2026-11-01 01:00:00','dns','Browser','local/Browser123','blocked.test','',53,0,3,0,0,0)`,
	} {
		if err := sqlitex.ExecuteTransient(conn, sql, nil); err != nil {
			t.Fatal(err)
		}
	}
	for _, column := range []string{"local_ip TEXT DEFAULT ''", "local_port INTEGER DEFAULT 0", "ip_protocol INTEGER DEFAULT 0", "direction TEXT DEFAULT ''", "path TEXT DEFAULT ''", "country TEXT DEFAULT ''", "asn INTEGER DEFAULT 0", "as_owner TEXT DEFAULT ''", "ended TEXT DEFAULT ''"} {
		if err := sqlitex.ExecuteTransient(conn, "ALTER TABLE history.connections ADD COLUMN "+column, nil); err != nil {
			t.Fatal(err)
		}
	}
	client := New(t.TempDir(), sqliteTestStore{conn})
	if err := sqlitex.ExecuteTransient(conn, "ALTER TABLE history.connections ADD COLUMN extra_data BLOB", nil); err != nil {
		t.Fatal(err)
	}
	request := detailRequest{RequestID: "req1", Since: "2026-11-01 00:00:00", Until: "2026-11-02 00:00:00", Limit: 1}
	data, _ := json.Marshal(request)
	first := client.queryDetail(context.Background(), data)
	if first.Error != "" || len(first.Records) != 1 || first.Records[0].ID != "a" ||
		first.Records[0].ProfileID != "local/Browser123" || first.Records[0].Verdict != 2 || first.NextCursor == nil {
		t.Fatalf("unexpected first page: %+v", first)
	}
	request.Cursor.Started, request.Cursor.ID = first.NextCursor.Started, first.NextCursor.ID
	data, _ = json.Marshal(request)
	second := client.queryDetail(context.Background(), data)
	if second.Error != "" || len(second.Records) != 1 || second.Records[0].ID != "b" {
		t.Fatalf("unexpected second page: %+v", second)
	}
	request.Cursor.Started, request.Cursor.ID = "", ""
	request.BlockedOnly = true
	data, _ = json.Marshal(request)
	blocked := client.queryDetail(context.Background(), data)
	if blocked.Error != "" || len(blocked.Records) != 1 || blocked.Records[0].ID != "b" || blocked.Records[0].Verdict != 3 {
		t.Fatalf("unexpected blocked results: %+v", blocked)
	}
}

func TestBoundedLabelsRemainDistinct(t *testing.T) {
	a := boundedLabel(strings.Repeat("a", 300) + "x")
	b := boundedLabel(strings.Repeat("a", 300) + "y")
	if len(a) > 255 || len(b) > 255 || a == b {
		t.Fatalf("invalid bounded labels: %q %q", a, b)
	}
}
