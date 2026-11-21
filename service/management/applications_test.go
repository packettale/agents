package management

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/packettale/agents/service/netenv"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

func TestApplicationCatalogueUsesProfileIDsAndBoundedPages(t *testing.T) {
	conn, err := sqlite.OpenConn(":memory:", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := sqlitex.ExecuteTransient(conn, `CREATE TABLE connections (id TEXT, profile TEXT, profile_name TEXT, started TEXT, internal INTEGER,path TEXT DEFAULT '')`, nil); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 201; i++ {
		sql := fmt.Sprintf(`INSERT INTO connections VALUES ('%d','local/App%03d','Shared display name','2026-01-01 00:00:00',0,'')`, i, i)
		if err := sqlitex.ExecuteTransient(conn, sql, nil); err != nil {
			t.Fatal(err)
		}
	}
	for _, sql := range []string{
		`INSERT INTO connections VALUES ('new','local/App000','Renamed app','2026-01-02 00:00:00',0,'')`,
		`INSERT INTO connections VALUES ('internal','local/Internal','Internal','2026-01-01',1,'')`,
		`INSERT INTO connections VALUES ('special','special/System','Special','2026-01-01',0,'')`,
	} {
		if err := sqlitex.ExecuteTransient(conn, sql, nil); err != nil {
			t.Fatal(err)
		}
	}
	calls := 0
	names := map[string]string{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/device/applications/" || r.Header.Get("Authorization") != "Bearer credential" {
			t.Error("unexpected catalogue request")
		}
		var batch struct {
			Applications []struct {
				ProfileID string `json:"profile_id"`
				Name      string `json:"name"`
			} `json:"applications"`
		}
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Error(err)
		}
		if len(batch.Applications) > 100 {
			t.Errorf("unbounded page: %d", len(batch.Applications))
		}
		for _, row := range batch.Applications {
			names[row.ProfileID] = row.Name
		}
		calls++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	dir := t.TempDir()
	client := New(dir, sqliteTestStore{conn})
	client.httpClient = server.Client()
	if err := writePrivateJSON(filepath.Join(dir, stateFile), State{DeviceID: "device", Credential: "credential"}); err != nil {
		t.Fatal(err)
	}
	if err := client.flushApplicationCatalogue(context.Background(), Config{ServerURL: server.URL}); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("unsupported server received inventory")
	}
	client.applicationCatalogueEnabled.Store(true)
	if err := client.flushApplicationCatalogue(context.Background(), Config{ServerURL: server.URL}); err != nil {
		t.Fatal(err)
	}
	if len(names) != 201 || calls != 11 || names["local/App000"] != "Renamed app" {
		t.Fatalf("wrong identity catalogue: profiles=%d pages=%d first=%s", len(names), calls, names["local/App000"])
	}
}

func TestApplicationCatalogueFailureDoesNotAlterCredentials(t *testing.T) {
	conn, err := sqlite.OpenConn(":memory:", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := sqlitex.ExecuteTransient(conn, `CREATE TABLE connections (id TEXT, profile TEXT, profile_name TEXT, started TEXT, internal INTEGER,path TEXT DEFAULT '')`, nil); err != nil {
		t.Fatal(err)
	}
	if err := sqlitex.ExecuteTransient(conn, `INSERT INTO connections VALUES ('1','local/App','App','2026-01-01',0,'')`, nil); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer server.Close()
	dir := t.TempDir()
	client := New(dir, sqliteTestStore{conn})
	client.httpClient = server.Client()
	client.applicationCatalogueEnabled.Store(true)
	if err := writePrivateJSON(filepath.Join(dir, stateFile), State{DeviceID: "device", Credential: "credential"}); err != nil {
		t.Fatal(err)
	}
	if err := client.flushApplicationCatalogue(context.Background(), Config{ServerURL: server.URL}); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("expected bounded upload failure: %v", err)
	}
	if state, err := readIdentity(dir); err != nil || state.Credential != "credential" {
		t.Fatal("catalogue failure altered enrollment")
	}
}

func TestEmptyApplicationCatalogueStillReportsNetworkAddresses(t *testing.T) {
	conn, err := sqlite.OpenConn(":memory:", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := sqlitex.ExecuteTransient(conn, `CREATE TABLE connections (id TEXT, profile TEXT, profile_name TEXT, started TEXT, internal INTEGER,path TEXT DEFAULT '')`, nil); err != nil {
		t.Fatal(err)
	}
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var report map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			t.Fatal(err)
		}
		if string(report["applications"]) != "[]" || report["interface_addresses"] == nil || string(report["interface_addresses"]) == "null" {
			t.Error("missing empty-catalogue network snapshot")
		}
		calls++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	dir := t.TempDir()
	client := New(dir, sqliteTestStore{conn})
	client.httpClient = server.Client()
	client.applicationCatalogueEnabled.Store(true)
	if err := writePrivateJSON(filepath.Join(dir, stateFile), State{DeviceID: "device", Credential: "credential"}); err != nil {
		t.Fatal(err)
	}
	if err := client.flushApplicationCatalogue(context.Background(), Config{ServerURL: server.URL}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("network snapshots: %d", calls)
	}
}

func TestCatalogueLocalAddressFollowsConnectionAndRejectsStaleSource(t *testing.T) {
	rows := []netenv.InterfaceAddress{{Interface: "Ethernet", Address: "10.23.45.67"}, {Interface: "VPN", Address: "fd00::2"}}
	if got := catalogueLocalAddress(rows, nil); got != "" {
		t.Fatalf("guessed first adapter: %s", got)
	}
	source := "fd00::2"
	if got := catalogueLocalAddress(rows, &source); got != source {
		t.Fatalf("lost VPN IPv6 source: %s", got)
	}
	source = "10.23.45.67"
	if got := catalogueLocalAddress(rows, &source); got != source {
		t.Fatalf("lost changed source: %s", got)
	}
	source = "10.0.0.99"
	if got := catalogueLocalAddress(rows, &source); got != "" {
		t.Fatalf("reported disappeared interface: %s", got)
	}
}
