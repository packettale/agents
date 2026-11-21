package netquery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/packettale/agents/service/management"
	"github.com/packettale/agents/service/netquery/orm"
	"github.com/packettale/agents/service/network"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

func openSummaryDatabase(t testing.TB, historyPath string) *Database {
	t.Helper()
	conn, err := sqlite.OpenConn(":memory:", 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	schema, err := orm.GenerateTableSchema("connections", Conn{})
	if err != nil {
		t.Fatal(err)
	}
	db := &Database{Schema: schema, writeConn: conn, historyPath: historyPath}
	if err := db.ApplyMigrations(); err != nil {
		t.Fatal(err)
	}
	return db
}

func summaryDatabase(t testing.TB) (*Database, management.CompactSummaryStore) {
	t.Helper()
	db := openSummaryDatabase(t, "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "history.db")))
	store, ok := any(db).(management.CompactSummaryStore)
	if !ok {
		t.Fatal("netquery does not implement durable compact capture")
	}
	if ready, err := store.ConfigureCompactSummaries(context.Background(), "endpoint-a", true); err != nil || !ready {
		t.Fatalf("enable capture: %v", err)
	}
	return db, store
}

func decodeSummary(t *testing.T, delivery *management.CompactDelivery) management.CompactBatch {
	t.Helper()
	if delivery == nil {
		t.Fatal("compact summary missing")
	}
	var batch management.CompactBatch
	if err := json.Unmarshal(delivery.Body, &batch); err != nil {
		t.Fatal(err)
	}
	return batch
}

func TestCompactCaptureWorksWithoutRawHistoryAndDoesNotRecountSaves(t *testing.T) {
	db, store := summaryDatabase(t)
	ctx := context.Background()
	conn := Conn{ID: "process-connection", ProfileID: "local/browser", ProfileName: "Browser", Type: "ip", Domain: "example.test", ActiveVerdict: network.VerdictAccept, Started: time.Now(), Active: true}
	conn.ID = makeNqIDFromParts("process", "connection", conn.Started.Unix())
	if err := db.Save(ctx, conn, false); err != nil {
		t.Fatal(err)
	}
	if err := db.Save(ctx, conn, false); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateBandwidth(ctx, false, conn.ProfileID, "process", "connection", conn.Started.Unix(), 200, 100); err != nil {
		t.Fatal(err)
	}
	var raw int
	if err := sqlitex.Execute(db.writeConn, "SELECT count(*) FROM history.connections", &sqlitex.ExecOptions{ResultFunc: func(s *sqlite.Stmt) error { raw = s.ColumnInt(0); return nil }}); err != nil {
		t.Fatal(err)
	}
	if raw != 0 {
		t.Fatal("compact capture forced raw history storage")
	}
	delivery, err := store.NextCompactSummary(ctx, "endpoint-a")
	if err != nil {
		t.Fatal(err)
	}
	batch := decodeSummary(t, delivery)
	if len(batch.Hourly) != 1 || batch.Hourly[0].Allowed != 1 || batch.Hourly[0].BytesReceived != 200 || batch.Hourly[0].BytesSent != 100 {
		t.Fatalf("incorrect hourly capture: %+v", batch.Hourly)
	}
	if len(batch.Destinations) != 1 || batch.Destinations[0].ProfileID != "local/browser" || batch.Destinations[0].Host != "example.test" || batch.Destinations[0].Allowed != 1 || batch.Destinations[0].BytesSent != 100 {
		t.Fatalf("incorrect identity/destination counters: %+v", batch.Destinations)
	}
}

func TestCompactPendingDeliveryIsImmutableWhileNewTrafficAccumulates(t *testing.T) {
	db, store := summaryDatabase(t)
	ctx := context.Background()
	conn := Conn{ID: "process-connection", ProfileID: "local/browser", ProfileName: "Browser", Type: "ip", Domain: "example.test", ActiveVerdict: network.VerdictAccept, Started: time.Now()}
	conn.ID = makeNqIDFromParts("process", "connection", conn.Started.Unix())
	if err := db.Save(ctx, conn, false); err != nil {
		t.Fatal(err)
	}
	first, err := store.NextCompactSummary(ctx, "endpoint-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateBandwidth(ctx, false, conn.ProfileID, "process", "connection", conn.Started.Unix(), 30, 20); err != nil {
		t.Fatal(err)
	}
	retry, err := store.NextCompactSummary(ctx, "endpoint-a")
	if err != nil {
		t.Fatal(err)
	}
	if retry.Sequence != first.Sequence || !bytes.Equal(first.Body, retry.Body) {
		t.Fatal("pending payload changed with live traffic")
	}
	if err := store.AcknowledgeCompactSummary(ctx, "endpoint-a", first.StreamID, first.Sequence+1); err == nil {
		t.Fatal("wrong acknowledgment removed pending data")
	}
	if err := store.AcknowledgeCompactSummary(ctx, "endpoint-a", first.StreamID, first.Sequence); err != nil {
		t.Fatal(err)
	}
	second, err := store.NextCompactSummary(ctx, "endpoint-a")
	if err != nil {
		t.Fatal(err)
	}
	batch := decodeSummary(t, second)
	if batch.Sequence != 2 || len(batch.Hourly) != 1 || batch.Hourly[0].Allowed != 0 || batch.Hourly[0].BytesReceived != 30 {
		t.Fatalf("pending activity lost or recounted: %+v", batch)
	}
}

func TestCompactLongLivedBytesFollowObservationAcrossMidnight(t *testing.T) {
	db, store := summaryDatabase(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 3, 23, 59, 59, 0, time.UTC)
	db.summaryNow = func() time.Time { return now }
	conn := Conn{ID: "process-connection", ProfileID: "local/browser", ProfileName: "Browser", Type: "ip", Domain: "example.test", ActiveVerdict: network.VerdictAccept, Started: now}
	conn.ID = makeNqIDFromParts("process", "connection", conn.Started.Unix())
	if err := db.Save(ctx, conn, false); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateBandwidth(ctx, false, conn.ProfileID, "process", "connection", conn.Started.Unix(), 200, 100); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if err := db.UpdateBandwidth(ctx, false, conn.ProfileID, "process", "connection", conn.Started.Unix(), 300, 150); err != nil {
		t.Fatal(err)
	}
	delivery, err := store.NextCompactSummary(ctx, "endpoint-a")
	if err != nil {
		t.Fatal(err)
	}
	batch := decodeSummary(t, delivery)
	if len(batch.Hourly) != 2 || batch.Hourly[0].Hour != "2026-11-03T23:00:00Z" || batch.Hourly[1].Hour != "2026-11-04T00:00:00Z" || batch.Hourly[0].BytesReceived != 200 || batch.Hourly[1].BytesReceived != 300 || batch.Hourly[1].Allowed != 0 {
		t.Fatalf("midnight bandwidth attribution wrong: %+v", batch.Hourly)
	}
	if len(batch.Destinations) != 2 || batch.Destinations[0].Day != "2026-11-03" || batch.Destinations[1].Day != "2026-11-04" {
		t.Fatalf("midnight destination attribution wrong: %+v", batch.Destinations)
	}
}

func TestCompactInternalRecordsExcludedAndBlockedDNSCounted(t *testing.T) {
	db, store := summaryDatabase(t)
	ctx := context.Background()
	for i, internal := range []bool{false, true} {
		conn := Conn{ID: fmt.Sprint(i), ProfileID: "local/browser", ProfileName: "Browser", Type: "dns", Domain: "blocked.test", ActiveVerdict: network.VerdictBlock, Started: time.Now(), Internal: internal}
		if err := db.Save(ctx, conn, false); err != nil {
			t.Fatal(err)
		}
	}
	delivery, err := store.NextCompactSummary(ctx, "endpoint-a")
	if err != nil {
		t.Fatal(err)
	}
	batch := decodeSummary(t, delivery)
	if len(batch.Hourly) != 1 || batch.Hourly[0].Blocked != 1 || batch.Hourly[0].DNS != 1 || len(batch.Destinations) != 1 {
		t.Fatalf("internal or DNS counting incorrect: %+v", batch)
	}
}

func TestCompactDrainFailureKeepsPendingCounters(t *testing.T) {
	db, store := summaryDatabase(t)
	ctx := context.Background()
	conn := Conn{ID: "one", ProfileID: "local/browser", ProfileName: "Browser", Type: "ip", Domain: "example.test", ActiveVerdict: network.VerdictAccept, Started: time.Now()}
	if err := db.Save(ctx, conn, false); err != nil {
		t.Fatal(err)
	}
	if err := sqlitex.ExecuteScript(db.writeConn, `CREATE TRIGGER management.fail_queue BEFORE DELETE ON hours BEGIN SELECT RAISE(ABORT,'simulated disk failure'); END;`, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.NextCompactSummary(ctx, "endpoint-a"); err == nil {
		t.Fatal("expected staging failure")
	}
	if err := sqlitex.Execute(db.writeConn, "DROP TRIGGER management.fail_queue", nil); err != nil {
		t.Fatal(err)
	}
	delivery, err := store.NextCompactSummary(ctx, "endpoint-a")
	if err != nil {
		t.Fatal(err)
	}
	batch := decodeSummary(t, delivery)
	if batch.Sequence != 1 || len(batch.Hourly) != 1 || batch.Hourly[0].Allowed != 1 {
		t.Fatalf("failed drain lost counters or advanced sequence: %+v", batch)
	}
}

func TestCompactCapturePreservesLiveAndHistoryUnionSchema(t *testing.T) {
	db, _ := summaryDatabase(t)
	if err := sqlitex.Execute(db.writeConn, "SELECT count(*) FROM (SELECT * FROM main.connections UNION ALL SELECT * FROM history.connections)", nil); err != nil {
		t.Fatalf("compact bookkeeping broke the existing connection query schema: %v", err)
	}
}

func TestCompactQueueSurvivesAbruptProcessExit(t *testing.T) {
	if path := os.Getenv("PACKETTALE_SUMMARY_CRASH_FIXTURE"); path != "" {
		db := openSummaryDatabase(t, "file:"+filepath.ToSlash(filepath.Join(path, "history.db")))
		if _, err := db.ConfigureCompactSummaries(context.Background(), "endpoint-a", true); err != nil {
			t.Fatal(err)
		}
		conn := Conn{ID: "one", ProfileID: "local/browser", ProfileName: "Browser", Type: "ip", Domain: "example.test", ActiveVerdict: network.VerdictAccept, Started: time.Now()}
		if err := db.Save(context.Background(), conn, false); err != nil {
			t.Fatal(err)
		}
		if _, err := db.NextCompactSummary(context.Background(), "endpoint-a"); err != nil {
			t.Fatal(err)
		}
		os.Exit(0) // Intentionally skip SQLite close and test cleanup in this child.
	}
	path := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCompactQueueSurvivesAbruptProcessExit$", "-test.timeout=15s")
	cmd.Env = append(os.Environ(), "PACKETTALE_SUMMARY_CRASH_FIXTURE="+path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("capture child failed: %v: %s", err, output)
	}
	db := openSummaryDatabase(t, "file:"+filepath.ToSlash(filepath.Join(path, "history.db")))
	ready, err := db.ConfigureCompactSummaries(context.Background(), "endpoint-a", false)
	if err != nil || !ready {
		t.Fatalf("persisted offline capture did not resume: %v", err)
	}
	delivery, err := db.NextCompactSummary(context.Background(), "endpoint-a")
	if err != nil {
		t.Fatal(err)
	}
	batch := decodeSummary(t, delivery)
	if batch.Sequence != 1 || len(batch.Hourly) != 1 || batch.Hourly[0].Allowed != 1 {
		t.Fatalf("pending committed delivery lost on process exit: %+v", batch)
	}
}

func TestCompactQueuePagesRemainBoundedAndPreserveAllDestinations(t *testing.T) {
	db, store := summaryDatabase(t)
	ctx := context.Background()
	for i := 0; i < 451; i++ {
		conn := Conn{ID: fmt.Sprint(i), ProfileID: "local/browser", ProfileName: "Browser", Type: "ip", Domain: fmt.Sprintf("host-%d.test", i), ActiveVerdict: network.VerdictAccept, Started: time.Now()}
		if err := db.Save(ctx, conn, false); err != nil {
			t.Fatal(err)
		}
	}
	total, hours, pages := 0, int64(0), 0
	for {
		delivery, err := store.NextCompactSummary(ctx, "endpoint-a")
		if err != nil {
			t.Fatal(err)
		}
		if delivery == nil {
			break
		}
		batch := decodeSummary(t, delivery)
		if len(batch.Destinations) > 200 || len(batch.Hourly) > 24 || len(delivery.Body) > 1024*1024 {
			t.Fatal("unbounded delivery")
		}
		total += len(batch.Destinations)
		for _, row := range batch.Hourly {
			hours += row.Allowed
		}
		pages++
		if err := store.AcknowledgeCompactSummary(ctx, "endpoint-a", delivery.StreamID, delivery.Sequence); err != nil {
			t.Fatal(err)
		}
	}
	if total != 451 || hours != 451 || pages != 3 {
		t.Fatalf("pagination lost or duplicated data: destinations=%d observations=%d pages=%d", total, hours, pages)
	}
}

func TestCompactEnrollmentSeparatesPendingData(t *testing.T) {
	db, store := summaryDatabase(t)
	ctx := context.Background()
	conn := Conn{ID: "one", ProfileID: "local/browser", ProfileName: "Browser", Type: "ip", Domain: "example.test", ActiveVerdict: network.VerdictAccept, Started: time.Now()}
	if err := db.Save(ctx, conn, false); err != nil {
		t.Fatal(err)
	}
	old, err := store.NextCompactSummary(ctx, "endpoint-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConfigureCompactSummaries(ctx, "endpoint-b", true); err != nil {
		t.Fatal(err)
	}
	fresh, err := store.NextCompactSummary(ctx, "endpoint-b")
	if err != nil {
		t.Fatal(err)
	}
	if old.StreamID == fresh.StreamID {
		t.Fatal("enrollment reused previous stream")
	}
	if err := store.AcknowledgeCompactSummary(ctx, "endpoint-b", old.StreamID, old.Sequence); err == nil {
		t.Fatal("old enrollment acknowledgment crossed identities")
	}
	retry, err := store.NextCompactSummary(ctx, "endpoint-a")
	if err != nil || !bytes.Equal(old.Body, retry.Body) {
		t.Fatal("new enrollment altered previous pending data")
	}
}

func TestCompactDatabaseFailureDoesNotPreventLocalConnectionStore(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "management-summary.db"), []byte("damaged summary database"), 0600); err != nil {
		t.Fatal(err)
	}
	db := openSummaryDatabase(t, "file:"+filepath.ToSlash(filepath.Join(dir, "history.db")))
	conn := Conn{ID: "one", ProfileID: "local/browser", ProfileName: "Browser", Type: "ip", Domain: "example.test", ActiveVerdict: network.VerdictAccept, Started: time.Now()}
	if err := db.Save(context.Background(), conn, false); err != nil {
		t.Fatalf("optional telemetry failure interrupted the local store: %v", err)
	}
	if _, err := db.ConfigureCompactSummaries(context.Background(), "endpoint-a", true); err == nil {
		t.Fatal("summary database damage must remain visible")
	}
}

func TestCompactInactiveNewEnrollmentStopsPreviousCapture(t *testing.T) {
	db, store := summaryDatabase(t)
	ctx := context.Background()
	conn := Conn{ID: "one", ProfileID: "local/browser", ProfileName: "Browser", Type: "ip", Domain: "before.test", ActiveVerdict: network.VerdictAccept, Started: time.Now()}
	if err := db.Save(ctx, conn, false); err != nil {
		t.Fatal(err)
	}
	old, err := store.NextCompactSummary(ctx, "endpoint-a")
	if err != nil {
		t.Fatal(err)
	}
	ready, err := store.ConfigureCompactSummaries(ctx, "endpoint-b", false)
	if err != nil || ready {
		t.Fatalf("new enrollment should remain inactive: %v", err)
	}
	conn.ID = "two"
	conn.Domain = "after.test"
	if err := db.Save(ctx, conn, false); err != nil {
		t.Fatal(err)
	}
	retry, err := store.NextCompactSummary(ctx, "endpoint-a")
	if err != nil || !bytes.Equal(old.Body, retry.Body) {
		t.Fatal("previous immutable outbox changed")
	}
	if err := store.AcknowledgeCompactSummary(ctx, "endpoint-a", old.StreamID, old.Sequence); err != nil {
		t.Fatal(err)
	}
	unexpected, err := store.NextCompactSummary(ctx, "endpoint-a")
	if err != nil || unexpected != nil {
		t.Fatalf("new enrollment traffic was captured for the previous identity: %v", err)
	}
}

func BenchmarkCompactSave(b *testing.B) {
	for _, active := range []bool{false, true} {
		b.Run(fmt.Sprintf("capture=%t", active), func(b *testing.B) {
			db := openSummaryDatabase(b, "file:"+filepath.ToSlash(filepath.Join(b.TempDir(), "history.db")))
			if active {
				if _, err := db.ConfigureCompactSummaries(context.Background(), "endpoint-a", true); err != nil {
					b.Fatal(err)
				}
			}
			conn := Conn{ProfileID: "local/browser", ProfileName: "Browser", Type: "ip", ActiveVerdict: network.VerdictAccept, Started: time.Now()}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				conn.ID = fmt.Sprint(i)
				conn.Domain = fmt.Sprintf("host-%d.test", i%200)
				if err := db.Save(context.Background(), conn, false); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestCompactDestinationsKeepCountryCountsSeparate(t *testing.T) {
	db, store := summaryDatabase(t)
	ctx := context.Background()
	for i, country := range []string{"US", "DE", "US", ""} {
		row := Conn{ID: fmt.Sprint(i), ProfileID: "local/browser", ProfileName: "Browser", Type: "ip", Domain: "multi.example", Country: country, ActiveVerdict: network.VerdictAccept, Started: time.Now()}
		if err := db.Save(ctx, row, false); err != nil {
			t.Fatal(err)
		}
	}
	delivery, err := store.NextCompactSummary(ctx, "endpoint-a")
	if err != nil {
		t.Fatal(err)
	}
	batch := decodeSummary(t, delivery)
	counts := map[string]int64{}
	for _, row := range batch.Destinations {
		counts[row.Country] += row.Allowed
	}
	if len(counts) != 3 || counts["US"] != 2 || counts["DE"] != 1 || counts[""] != 1 || batch.Hourly[0].Allowed != 4 {
		t.Fatalf("country counters changed totals: %+v", batch)
	}
}

func TestCountryAggregateSchemaUpgradePreservesCounters(t *testing.T) {
	conn, err := sqlite.OpenConn(":memory:", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	err = sqlitex.ExecuteScript(conn, `ATTACH DATABASE ':memory:' AS management;
 CREATE TABLE management.destinations(capture_id INTEGER,day TEXT,profile_id TEXT,app TEXT,host TEXT,allowed INTEGER,blocked INTEGER,bytes_sent INTEGER,bytes_received INTEGER,PRIMARY KEY(capture_id,day,profile_id,app,host));
 INSERT INTO management.destinations VALUES(1,'2026-11-10','local/app','App','same.test',4,2,100,200);`, nil)
	if err != nil {
		t.Fatal(err)
	}
	db := &Database{writeConn: conn}
	if err := db.migrateDestinationCountries(); err != nil {
		t.Fatal(err)
	}
	if err := sqlitex.ExecuteTransient(conn, `INSERT INTO management.destinations VALUES(1,'2026-11-10','local/app','App','same.test','US',3,0,50,60)`, nil); err != nil {
		t.Fatal(err)
	}
	err = sqlitex.ExecuteTransient(conn, `SELECT count(*),sum(allowed),sum(blocked),sum(bytes_sent),sum(bytes_received) FROM management.destinations`, &sqlitex.ExecOptions{ResultFunc: func(s *sqlite.Stmt) error {
		if s.ColumnInt(0) != 2 || s.ColumnInt(1) != 7 || s.ColumnInt(2) != 2 || s.ColumnInt(3) != 150 || s.ColumnInt(4) != 260 {
			t.Fatal("schema change altered counters")
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCompactCategoriesPreserveLocalHistoryAndRetryWithoutRecounting(t *testing.T) {
	db, store := summaryDatabase(t)
	ctx := context.Background()
	conn := Conn{ID: "blocked-1", ProfileID: "local/browser", ProfileName: "Browser", Type: "ip", Domain: "example.test", Country: "US", ActiveVerdict: network.VerdictBlock, Started: time.Now(), ExtraData: json.RawMessage(`{"blockedByLists":["TRAC","MAL","MAL"]}`)}
	if err := db.Save(ctx, conn, true); err != nil {
		t.Fatal(err)
	}
	if err := db.Save(ctx, conn, true); err != nil {
		t.Fatal(err)
	}
	first, err := store.NextCompactSummary(ctx, "endpoint-a")
	if err != nil {
		t.Fatal(err)
	}
	batch := decodeSummary(t, first)
	if len(batch.Categories) != 1 || batch.Categories[0].Blocked != 1 || !reflect.DeepEqual(batch.Categories[0].Lists, []string{"MAL", "TRAC"}) || batch.Categories[0].Host != "example.test" || batch.Categories[0].Country != "US" {
		t.Fatalf("wrong category counts: %+v", batch.Categories)
	}
	conn.ID = "blocked-2"
	if err := db.Save(ctx, conn, true); err != nil {
		t.Fatal(err)
	}
	retry, err := store.NextCompactSummary(ctx, "endpoint-a")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Body, retry.Body) {
		t.Fatal("pending summary changed during retry")
	}
	if err := store.AcknowledgeCompactSummary(ctx, "endpoint-a", first.StreamID, first.Sequence); err != nil {
		t.Fatal(err)
	}
	next, err := store.NextCompactSummary(ctx, "endpoint-a")
	if err != nil {
		t.Fatal(err)
	}
	batch = decodeSummary(t, next)
	if len(batch.Categories) != 1 || batch.Categories[0].Blocked != 1 {
		t.Fatalf("new observation lost or duplicated: %+v", batch.Categories)
	}
	var raw int
	if err := sqlitex.Execute(db.writeConn, "SELECT count(*) FROM history.connections", &sqlitex.ExecOptions{ResultFunc: func(s *sqlite.Stmt) error { raw = s.ColumnInt(0); return nil }}); err != nil {
		t.Fatal(err)
	}
	if raw != 2 {
		t.Fatalf("local detailed history changed: %d", raw)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(strings.TrimPrefix(db.historyPath, "file:")), "management-events.db")); !os.IsNotExist(err) {
		t.Fatalf("unsolicited raw spool exists: %v", err)
	}
}
