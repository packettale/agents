package management

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

func detailFixture(t *testing.T) (*Client, *sqlite.Conn) {
	t.Helper()
	conn, err := sqlite.OpenConn(":memory:", 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	for _, query := range []string{"ATTACH DATABASE ':memory:' AS history", `CREATE TABLE history.connections(
 id TEXT, started TEXT, type TEXT DEFAULT 'dns', profile_name TEXT DEFAULT 'Browser',
 profile TEXT DEFAULT 'local/Browser123', domain TEXT DEFAULT 'blocked.example.',
 local_ip TEXT DEFAULT '', local_port INTEGER DEFAULT 0, ip_protocol INTEGER DEFAULT 0,
 direction TEXT DEFAULT '', path TEXT DEFAULT '',country TEXT DEFAULT '',asn INTEGER DEFAULT 0,
 as_owner TEXT DEFAULT '',ended TEXT DEFAULT '',remote_ip TEXT DEFAULT '<nil>', remote_port INTEGER DEFAULT 0, verdict INTEGER DEFAULT 3,
 bytes_sent INTEGER DEFAULT 0, bytes_received INTEGER DEFAULT 0, internal INTEGER DEFAULT 0, extra_data BLOB)`} {
		if err := sqlitex.ExecuteTransient(conn, query, nil); err != nil {
			t.Fatal(err)
		}
	}
	return New(t.TempDir(), sqliteTestStore{conn}), conn
}

func insertDetail(t *testing.T, conn *sqlite.Conn, id string, extra any) {
	t.Helper()
	if err := sqlitex.ExecuteTransient(conn, `INSERT INTO history.connections(id,started,extra_data) VALUES (?, '2026-11-05 01:00:00', ?)`, &sqlitex.ExecOptions{Args: []any{id, extra}}); err != nil {
		t.Fatal(err)
	}
}

func detailPage(t *testing.T, client *Client, request detailRequest) detailResponse {
	t.Helper()
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return client.queryDetail(context.Background(), data)
}

func detailTestRequest() detailRequest {
	return detailRequest{RequestID: "detail-test", Since: "2026-11-05 00:00:00", Until: "2026-11-06 00:00:00", Limit: 100}
}

func encodedDetailRecords(t *testing.T, response detailResponse) []map[string]any {
	t.Helper()
	if response.Error != "" {
		t.Fatal(response.Error)
	}
	data, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Records []map[string]any `json:"records"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result.Records
}

func TestDetailReturnsStoredReasonAndEmptyDNSAddress(t *testing.T) {
	client, conn := detailFixture(t)
	insertDetail(t, conn, "blocked", []byte(`{"reason":{"Msg":"blocked by mandatory management policy","Context":{"private":"must not be sent"}}}`))
	records := encodedDetailRecords(t, detailPage(t, client, detailTestRequest()))
	if len(records) != 1 {
		t.Fatalf("records: %+v", records)
	}
	if records[0]["reason"] != "blocked by mandatory management policy" {
		t.Errorf("stored reason missing: %+v", records[0])
	}
	if records[0]["remote_ip"] != "" {
		t.Errorf("DNS without an IP must not expose a Go nil marker: %+v", records[0])
	}
	if _, exists := records[0]["extra_data"]; exists {
		t.Fatal("unbounded extra data was transferred")
	}
}

func TestDetailToleratesMissingAndMalformedReason(t *testing.T) {
	for name, extra := range map[string]any{"null": nil, "invalid": []byte("{broken"), "absent": []byte(`{}`), "number": []byte(`{"reason":{"Msg":3}}`), "object": []byte(`{"reason":{"Msg":{"message":"not text"}}}`), "lone-surrogates": []byte(`{"reason":{"Msg":"` + strings.Repeat(`\ud800`, 400) + `"}}`), "invalid-utf8": []byte(`{"reason":{"Msg":"` + strings.Repeat("\xff", 1024) + `"}}`)} {
		t.Run(name, func(t *testing.T) {
			client, conn := detailFixture(t)
			insertDetail(t, conn, name, extra)
			records := encodedDetailRecords(t, detailPage(t, client, detailTestRequest()))
			if len(records) != 1 || records[0]["reason"] != "" {
				t.Fatalf("invalid optional reason must not discard the connection: %+v", records)
			}
		})
	}
}

func TestDetailBoundsUnicodeReasonAndPaginatesWithoutLoss(t *testing.T) {
	client, conn := detailFixture(t)
	message := strings.Repeat("阻止🛡", 1000)
	extra, err := json.Marshal(map[string]any{"reason": map[string]any{"Msg": message}})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		insertDetail(t, conn, fmt.Sprintf("id%03d", i), extra)
	}
	request := detailTestRequest()
	seen := map[string]bool{}
	pages := 0
	for {
		response := detailPage(t, client, request)
		records := encodedDetailRecords(t, response)
		wire, err := json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		if len(wire) > 32768 {
			t.Fatalf("bounded relay page exceeded 32 KiB: %d", len(wire))
		}
		if pages == 0 && (len(records) == 0 || len(records) >= 100 || response.NextCursor == nil) {
			t.Fatalf("large reasons require bounded, resumable pages: %d records", len(records))
		}
		for _, record := range records {
			id := record["id"].(string)
			if seen[id] {
				t.Fatalf("duplicate cursor record: %s", id)
			}
			seen[id] = true
			reason, ok := record["reason"].(string)
			if !ok || reason == "" || len(reason) > 1024 || !utf8.ValidString(reason) || !strings.HasPrefix(message, reason) {
				t.Fatalf("invalid bounded Unicode reason: %q", reason)
			}
		}
		pages++
		if pages > 100 {
			t.Fatal("cursor did not advance")
		}
		if response.NextCursor == nil {
			break
		}
		request.Cursor.Started, request.Cursor.ID = response.NextCursor.Started, response.NextCursor.ID
	}
	if len(seen) != 100 {
		t.Fatalf("pagination lost records: %d", len(seen))
	}
}

func TestDetailRejectsIndividuallyOversizedRecord(t *testing.T) {
	client, conn := detailFixture(t)
	insertDetail(t, conn, "oversized", nil)
	if err := sqlitex.ExecuteTransient(conn, `UPDATE history.connections SET profile_name=?`, &sqlitex.ExecOptions{Args: []any{strings.Repeat("a", 40000)}}); err != nil {
		t.Fatal(err)
	}
	response := detailPage(t, client, detailTestRequest())
	if response.Error == "" || len(response.Records) != 0 {
		t.Fatal("oversized record must return an explicit error, not an unsendable page or a silent skip")
	}
}

func TestDetailDestinationAcceptsEquivalentExactNamesAndAddresses(t *testing.T) {
	client, conn := detailFixture(t)
	for _, row := range []struct{ id, domain, ip string }{
		{"dns1", "blocked.example.", ""}, {"dns2", "blocked.example", ""},
		{"subdomain", "sub.blocked.example.", ""}, {"other", "blocked.example.other.", ""},
		{"ipv4", "", "192.0.2.3"}, {"ipv6", "", "2001:db8::1"},
	} {
		insertDetail(t, conn, row.id, nil)
		if err := sqlitex.ExecuteTransient(conn, "UPDATE history.connections SET domain=?,remote_ip=? WHERE id=?", &sqlitex.ExecOptions{Args: []any{row.domain, row.ip, row.id}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range []struct{ host, ids string }{
		{"blocked.example", "dns1,dns2"}, {"blocked.example.", "dns1,dns2"},
		{"  BLOCKED.Example.  ", "dns1,dns2"}, {"192.0.2.3", "ipv4"},
		{"::ffff:192.0.2.3", "ipv4"}, {"2001:0DB8:0:0:0:0:0:1", "ipv6"},
		{"blocked%", ""}, {"blocked_example", ""}, {"example", ""}, {".", ""},
	} {
		t.Run(test.host, func(t *testing.T) {
			request := detailTestRequest()
			request.Host = test.host
			response := detailPage(t, client, request)
			if response.Error != "" {
				t.Fatal(response.Error)
			}
			ids := make([]string, 0, len(response.Records))
			for _, row := range response.Records {
				ids = append(ids, row.ID)
			}
			if got := strings.Join(ids, ","); got != test.ids {
				t.Errorf("exact destination search returned %q, want %q", got, test.ids)
			}
		})
	}
}

func TestDetailRejectsMultipleTerminalDNSDots(t *testing.T) {
	client, conn := detailFixture(t)
	insertDetail(t, conn, "blocked", nil)
	for _, host := range []string{"blocked.example..", ".."} {
		request := detailTestRequest()
		request.Host = host
		if response := detailPage(t, client, request); response.Error == "" {
			t.Errorf("malformed destination %q must not alias a valid domain", host)
		}
	}
}

func TestDetailContinuesPastLongDNSRecordID(t *testing.T) {
	client, conn := detailFixture(t)
	// Nameserver includes the complete DNS question in the ID; netquery also
	// prefixes process identity. Valid DNS names can easily exceed128 bytes.
	id := "-2-0-127.0.0.1-65535-#65535-" + strings.Repeat("long-label.", 20) + "example.A"
	insertDetail(t, conn, id, nil)
	insertDetail(t, conn, "next-record", nil)
	request := detailTestRequest()
	request.Limit = 1
	first := detailPage(t, client, request)
	if first.Error != "" || first.NextCursor == nil || len(first.Records) != 1 || first.Records[0].ID != id {
		t.Fatalf("first page: %+v", first)
	}
	request.Cursor.Started, request.Cursor.ID = first.NextCursor.Started, first.NextCursor.ID
	second := detailPage(t, client, request)
	if second.Error != "" || len(second.Records) != 1 || second.Records[0].ID != "next-record" || second.NextCursor != nil {
		t.Fatalf("continuation lost a valid long DNS record ID: %+v", second)
	}
	request.Cursor.ID = strings.Repeat("a", 513)
	if response := detailPage(t, client, request); response.Error == "" {
		t.Fatal("oversized cursor was accepted")
	}
}

func TestDetailIncludesConnectionMetadata(t *testing.T) {
	client, conn := detailFixture(t)
	insertDetail(t, conn, "details", nil)
	err := sqlitex.ExecuteTransient(conn, `UPDATE history.connections SET local_ip='10.2.0.4',local_port=49152,remote_ip='1.1.1.1',remote_port=443,ip_protocol=6,direction='outbound',path='C:\Apps\browser.exe',country='US',asn=13335,as_owner='Cloudflare',ended='2026-11-05 01:01:00'`, nil)
	if err != nil {
		t.Fatal(err)
	}
	records := encodedDetailRecords(t, detailPage(t, client, detailTestRequest()))
	if len(records) != 1 || records[0]["country"] != "US" || records[0]["protocol"] != float64(6) || records[0]["path"] != `C:\Apps\browser.exe` || records[0]["local_ip"] != "10.2.0.4" || records[0]["as_owner"] != "Cloudflare" {
		t.Fatalf("missing metadata: %+v", records)
	}
}

func TestDetailCountryAndProfileFiltersRemainExact(t *testing.T) {
	client, conn := detailFixture(t)
	for _, id := range []string{"us", "de", "other"} {
		insertDetail(t, conn, id, nil)
	}
	if err := sqlitex.ExecuteTransient(conn, `UPDATE history.connections SET profile='local/Browser',country=CASE WHEN id='de' THEN 'DE' ELSE 'US' END`, nil); err != nil {
		t.Fatal(err)
	}
	if err := sqlitex.ExecuteTransient(conn, `UPDATE history.connections SET profile='local/Other' WHERE id='other'`, nil); err != nil {
		t.Fatal(err)
	}
	request := detailTestRequest()
	request.Country = "US"
	request.ProfileID = "local/Browser"
	records := encodedDetailRecords(t, detailPage(t, client, request))
	if len(records) != 1 || records[0]["id"] != "us" {
		t.Fatalf("cross-scope connection details: %+v", records)
	}
	request.Country = "../../us"
	if detailPage(t, client, request).Error == "" {
		t.Fatal("invalid country filter accepted")
	}
}

func TestUnknownNativeCountryMatchesUnknownFilter(t *testing.T) {
	client, conn := detailFixture(t)
	insertDetail(t, conn, "unknown-country", nil)
	if err := sqlitex.ExecuteTransient(conn, `UPDATE history.connections SET country='__'`, nil); err != nil {
		t.Fatal(err)
	}
	request := detailTestRequest()
	request.Country = "unknown"
	rows := encodedDetailRecords(t, detailPage(t, client, request))
	if len(rows) != 1 || rows[0]["country"] != "" {
		t.Fatalf("native unknown country was lost: %+v", rows)
	}
}

func TestDetailTotalCountsFilteredMatchesBeforeCursor(t *testing.T) {
	client, conn := detailFixture(t)
	for _, id := range []string{"one", "two", "three"} {
		insertDetail(t, conn, id, []byte(`{"blockedByLists":["AA-AD","SFA-P","AA-AD"],"private":"never expose"}`))
	}
	request := detailTestRequest()
	request.Limit = 1
	first := detailPage(t, client, request)
	if first.Error != "" || first.Total == nil || *first.Total != 3 || len(first.Records) != 1 || first.NextCursor == nil {
		t.Fatalf("incorrect first count/page: %+v", first)
	}
	if len(first.Records[0].BlockedByLists) != 2 {
		t.Fatalf("lost/doubled categories: %+v", first.Records[0].BlockedByLists)
	}
	wire, _ := json.Marshal(first)
	if strings.Contains(string(wire), "never expose") || strings.Contains(string(wire), "extra_data") {
		t.Fatal("raw optional metadata escaped")
	}
	request.Cursor.Started, request.Cursor.ID = first.NextCursor.Started, first.NextCursor.ID
	second := detailPage(t, client, request)
	if second.Total == nil || *second.Total != 3 {
		t.Fatal("count incorrectly applied cursor filter")
	}
	request = detailTestRequest()
	request.App = "unobserved"
	empty := detailPage(t, client, request)
	if empty.Error != "" || empty.Total == nil || *empty.Total != 0 || len(empty.Records) != 0 {
		t.Fatal("empty filtered total is not zero")
	}
}

func TestDetailListsBoundsAndMalformedData(t *testing.T) {
	for _, data := range []string{"", `{broken`, `{"blockedByLists":{}}`, `{"blockedByLists":[1]}`} {
		if len(detailLists(data)) != 0 {
			t.Fatal("malformed category attribution")
		}
	}
	values := []string{"", "bad\nlabel", strings.Repeat("x", 65), "AA-AD", "AA-AD"}
	for i := 0; i < 100; i++ {
		values = append(values, fmt.Sprintf("list-%d", i))
	}
	raw, _ := json.Marshal(map[string]any{"blockedByLists": values})
	if got := detailLists(string(raw)); len(got) != 64 || got[0] != "AA-AD" {
		t.Fatalf("category bounds/dedupe failed: %+v", got)
	}
}
