package netquery

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/packettale/agents/service/management"
	"github.com/packettale/agents/service/netquery/orm"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

//go:embed management_summary.sql
var managementSummarySchema string

// Upgrade the local aggregate key without rescanning raw connection history.
func (db *Database) migrateDestinationCountries() error {
	var found bool
	if err := sqlitex.ExecuteTransient(db.writeConn, "PRAGMA management.table_info(destinations)", &sqlitex.ExecOptions{ResultFunc: func(stmt *sqlite.Stmt) error {
		found = found || stmt.ColumnText(1) == "country"
		return nil
	}}); err != nil {
		return err
	}
	if found {
		return nil
	}
	return sqlitex.ExecuteScript(db.writeConn, `CREATE TABLE management.destinations_country (
 capture_id INTEGER NOT NULL,day TEXT NOT NULL,profile_id TEXT NOT NULL,app TEXT NOT NULL,host TEXT NOT NULL,country TEXT NOT NULL DEFAULT '',
 allowed INTEGER NOT NULL DEFAULT 0 CHECK(typeof(allowed)='integer' AND allowed>=0),
 blocked INTEGER NOT NULL DEFAULT 0 CHECK(typeof(blocked)='integer' AND blocked>=0),
 bytes_sent INTEGER NOT NULL DEFAULT 0 CHECK(typeof(bytes_sent)='integer' AND bytes_sent>=0),
 bytes_received INTEGER NOT NULL DEFAULT 0 CHECK(typeof(bytes_received)='integer' AND bytes_received>=0),
 PRIMARY KEY(capture_id,day,profile_id,app,host,country));
INSERT INTO management.destinations_country SELECT capture_id,day,profile_id,app,host,'',allowed,blocked,bytes_sent,bytes_received FROM management.destinations;
DROP TABLE management.destinations;
ALTER TABLE management.destinations_country RENAME TO destinations;`, nil)
}

func (db *Database) setSummaryTime() {
	if db.summaryNow == nil {
		db.summaryTime = time.Now().Unix()
	} else {
		db.summaryTime = db.summaryNow().Unix()
	}
}

func (db *Database) initEnterpriseSummaries() error {
	uri := strings.TrimSuffix(db.historyPath, "history.db") + "management-summary.db"
	if err := sqlitex.ExecuteTransient(db.writeConn, "ATTACH DATABASE :path AS management", &sqlitex.ExecOptions{Named: map[string]any{":path": uri}}); err != nil {
		return err
	}
	for _, stmt := range []string{"PRAGMA management.journal_mode=WAL", "PRAGMA management.synchronous=NORMAL"} {
		if err := sqlitex.ExecuteTransient(db.writeConn, stmt, nil); err != nil {
			return err
		}
	}
	if err := sqlitex.ExecuteScript(db.writeConn, managementSummarySchema, nil); err != nil {
		return err
	}
	if err := db.migrateDestinationCountries(); err != nil {
		return err
	}
	if err := sqlitex.ExecuteTransient(db.writeConn, "CREATE TEMP TABLE management_counted(conn_id TEXT PRIMARY KEY,capture_id INTEGER NOT NULL)", nil); err != nil {
		return err
	}
	if err := db.writeConn.CreateFunction("management_now", &sqlite.FunctionImpl{NArgs: 0, Scalar: func(_ sqlite.Context, _ []sqlite.Value) (sqlite.Value, error) {
		return sqlite.IntegerValue(db.summaryTime), nil
	}}); err != nil {
		return err
	}
	// TEMP triggers resolve the unqualified write targets in the attached database.
	// Persistent changes for each trigger are in management-summary.db only.
	countBody := `
 INSERT INTO management_counted(conn_id,capture_id) SELECT NEW.id,id FROM management.capture WHERE active=1 ON CONFLICT(conn_id) DO UPDATE SET capture_id=excluded.capture_id;
 INSERT INTO hours(capture_id,hour,allowed,blocked,dns)
 SELECT id,(management_now()/3600)*3600,NEW.verdict IN(2,5,6,8),NEW.verdict IN(3,4),NEW.type='dns' FROM management.capture WHERE active=1
 ON CONFLICT(capture_id,hour) DO UPDATE SET allowed=allowed+excluded.allowed,blocked=blocked+excluded.blocked,dns=dns+excluded.dns;
 INSERT INTO destinations(capture_id,day,profile_id,app,host,country,allowed,blocked)
 SELECT id,date(management_now(),'unixepoch'),NEW.profile,COALESCE(NULLIF(NEW.profile_name,''),'Unknown'),COALESCE(NULLIF(NEW.domain,''),NULLIF(NEW.remote_ip,''),'Unknown'),CASE WHEN NEW.country GLOB '[A-Z][A-Z]' THEN NEW.country ELSE '' END,NEW.verdict IN(2,5,6,8),NEW.verdict IN(3,4) FROM management.capture WHERE active=1
 ON CONFLICT(capture_id,day,profile_id,app,host,country) DO UPDATE SET allowed=allowed+excluded.allowed,blocked=blocked+excluded.blocked;
 INSERT INTO categories(capture_id,day,profile_id,host,country,lists,blocked)
 SELECT id,date(management_now(),'unixepoch'),NEW.profile,COALESCE(NULLIF(NEW.domain,''),NULLIF(NEW.remote_ip,''),'Unknown'),CASE WHEN NEW.country GLOB '[A-Z][A-Z]' THEN NEW.country ELSE '' END,
 (SELECT json_group_array(value) FROM (SELECT DISTINCT value FROM json_each(CASE WHEN json_valid(NEW.extra_data) THEN json_extract(NEW.extra_data,'$.blockedByLists') ELSE '[]' END) WHERE type='text' AND length(value) BETWEEN 1 AND 64 ORDER BY value LIMIT 64)),1
 FROM management.capture WHERE active=1 AND NEW.verdict IN(3,4)
 ON CONFLICT(capture_id,day,profile_id,host,country,lists) DO UPDATE SET blocked=blocked+excluded.blocked;`
	for _, event := range []string{"INSERT", "UPDATE"} {
		stmt := fmt.Sprintf(`CREATE TEMP TRIGGER management_count_%s AFTER %s ON main.connections
 WHEN NEW.internal=0 AND NOT EXISTS(SELECT 1 FROM management_counted WHERE conn_id=NEW.id AND capture_id=(SELECT id FROM management.capture WHERE active=1)) AND NEW.verdict IN(2,3,4,5,6,8) AND EXISTS(SELECT 1 FROM management.capture WHERE active=1)
 BEGIN %s END`, strings.ToLower(event), event, countBody)
		if err := sqlitex.ExecuteScript(db.writeConn, stmt, nil); err != nil {
			return err
		}
	}
	if err := sqlitex.ExecuteScript(db.writeConn, `CREATE TEMP TRIGGER management_cleanup AFTER DELETE ON main.connections BEGIN DELETE FROM management_counted WHERE conn_id=OLD.id; END`, nil); err != nil {
		return err
	}
	return sqlitex.ExecuteScript(db.writeConn, `CREATE TEMP TRIGGER management_bandwidth AFTER UPDATE OF bytes_sent,bytes_received ON main.connections
 WHEN NEW.internal=0 AND EXISTS(SELECT 1 FROM management_counted WHERE conn_id=NEW.id AND capture_id=(SELECT id FROM management.capture WHERE active=1))
 AND (NEW.bytes_sent>OLD.bytes_sent OR NEW.bytes_received>OLD.bytes_received)
 BEGIN
 INSERT INTO hours(capture_id,hour,bytes_sent,bytes_received)
 VALUES((SELECT id FROM management.capture WHERE active=1),(management_now()/3600)*3600,MAX(NEW.bytes_sent-OLD.bytes_sent,0),MAX(NEW.bytes_received-OLD.bytes_received,0))
 ON CONFLICT(capture_id,hour) DO UPDATE SET bytes_sent=bytes_sent+excluded.bytes_sent,bytes_received=bytes_received+excluded.bytes_received;
 INSERT INTO destinations(capture_id,day,profile_id,app,host,country,bytes_sent,bytes_received)
 VALUES((SELECT id FROM management.capture WHERE active=1),date(management_now(),'unixepoch'),NEW.profile,COALESCE(NULLIF(NEW.profile_name,''),'Unknown'),COALESCE(NULLIF(NEW.domain,''),NULLIF(NEW.remote_ip,''),'Unknown'),CASE WHEN NEW.country GLOB '[A-Z][A-Z]' THEN NEW.country ELSE '' END,MAX(NEW.bytes_sent-OLD.bytes_sent,0),MAX(NEW.bytes_received-OLD.bytes_received,0))
 ON CONFLICT(capture_id,day,profile_id,app,host,country) DO UPDATE SET bytes_sent=bytes_sent+excluded.bytes_sent,bytes_received=bytes_received+excluded.bytes_received;
 END`, nil)
}

type compactCapture struct {
	ID        int64  `sqlite:"id"`
	StreamID  string `sqlite:"stream_id"`
	StartedAt int64  `sqlite:"started_at"`
	Sequence  int64  `sqlite:"sequence"`
	Active    bool   `sqlite:"active"`
}

func (db *Database) compactCapture(ctx context.Context, deviceID string) (compactCapture, error) {
	var rows []compactCapture
	err := orm.RunQuery(ctx, db.writeConn, "SELECT id,stream_id,started_at,sequence,active FROM management.capture WHERE device_id=:device", orm.WithNamedArgs(map[string]any{":device": deviceID}), orm.WithResult(&rows))
	if err != nil {
		return compactCapture{}, err
	}
	if len(rows) == 0 {
		return compactCapture{}, nil
	}
	return rows[0], nil
}

func (db *Database) ConfigureCompactSummaries(ctx context.Context, deviceID string, enable bool) (ready bool, err error) {
	if err = ctx.Err(); err != nil {
		return false, err
	}
	if deviceID == "" {
		return false, errors.New("empty compact capture identity")
	}
	if db.summaryErr != nil {
		if !enable {
			return false, nil
		}
		return false, db.summaryErr
	}
	db.l.Lock()
	defer db.l.Unlock()
	db.setSummaryTime()
	capture, err := db.compactCapture(ctx, deviceID)
	if err != nil {
		return false, err
	}
	if capture.ID == 0 && !enable {
		// Switching enrollment must stop accumulation for the previous owner,
		// even when the new server cannot enable compact reporting yet.
		err = sqlitex.Execute(db.writeConn, "UPDATE management.capture SET active=0 WHERE active=1", nil)
		return false, err
	}
	if capture.Active {
		return true, nil
	}
	if err = sqlitex.Execute(db.writeConn, "BEGIN IMMEDIATE", nil); err != nil {
		return false, err
	}
	defer func() {
		if err != nil {
			_ = sqlitex.Execute(db.writeConn, "ROLLBACK", nil)
		}
	}()
	if err = sqlitex.Execute(db.writeConn, "UPDATE management.capture SET active=0 WHERE active=1", nil); err != nil {
		return false, err
	}
	if err = sqlitex.Execute(db.writeConn, `INSERT INTO management.capture(device_id,stream_id,started_at,active) VALUES(:device,:stream,:started,1)
 ON CONFLICT(device_id) DO UPDATE SET active=1`, &sqlitex.ExecOptions{Named: map[string]any{":device": deviceID, ":stream": uuid.NewString(), ":started": db.summaryTime}}); err != nil {
		return false, err
	}
	// Seed only current live observations, never retained raw history.
	if err = sqlitex.Execute(db.writeConn, "UPDATE main.connections SET active=active", nil); err != nil {
		return false, err
	}
	err = sqlitex.Execute(db.writeConn, "COMMIT", nil)
	return err == nil, err
}

func (db *Database) NextCompactSummary(ctx context.Context, deviceID string) (delivery *management.CompactDelivery, err error) {
	if db.summaryErr != nil {
		return nil, db.summaryErr
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	db.l.Lock()
	defer db.l.Unlock()
	capture, err := db.compactCapture(ctx, deviceID)
	if err != nil || capture.ID == 0 {
		return nil, err
	}
	var pending []struct {
		Sequence int64  `sqlite:"sequence"`
		Body     []byte `sqlite:"body"`
	}
	params := map[string]any{":capture": capture.ID}
	if err = orm.RunQuery(ctx, db.writeConn, "SELECT sequence,body FROM management.outbox WHERE capture_id=:capture", orm.WithNamedArgs(params), orm.WithResult(&pending)); err != nil {
		return nil, err
	}
	if len(pending) > 0 {
		return &management.CompactDelivery{StreamID: capture.StreamID, Sequence: pending[0].Sequence, Body: pending[0].Body}, nil
	}
	if err = sqlitex.Execute(db.writeConn, "BEGIN IMMEDIATE", nil); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = sqlitex.Execute(db.writeConn, "ROLLBACK", nil)
		}
	}()
	batch := management.CompactBatch{StreamID: capture.StreamID, Sequence: capture.Sequence + 1, StartedAt: time.Unix(capture.StartedAt, 0).UTC().Format(time.RFC3339), Hourly: []management.CompactHour{}, Destinations: []management.CompactDestination{}, Categories: []management.CompactCategory{}}
	err = orm.RunQuery(ctx, db.writeConn, `SELECT strftime('%Y-%m-%dT%H:00:00Z',hour,'unixepoch') AS hour,allowed,blocked,dns,bytes_sent,bytes_received FROM management.hours WHERE capture_id=:capture ORDER BY hour LIMIT 24`, orm.WithNamedArgs(params), orm.WithResult(&batch.Hourly))
	if err != nil {
		return nil, err
	}
	err = orm.RunQuery(ctx, db.writeConn, `SELECT day,profile_id,app,host,country,allowed,blocked,bytes_sent,bytes_received FROM management.destinations WHERE capture_id=:capture ORDER BY rowid LIMIT 200`, orm.WithNamedArgs(params), orm.WithResult(&batch.Destinations))
	if err != nil {
		return nil, err
	}
	var categories []struct {
		Day       string `sqlite:"day"`
		ProfileID string `sqlite:"profile_id"`
		Host      string `sqlite:"host"`
		Country   string `sqlite:"country"`
		Lists     string `sqlite:"lists"`
		Blocked   int64  `sqlite:"blocked"`
	}
	err = orm.RunQuery(ctx, db.writeConn, "SELECT day,profile_id,host,country,lists,blocked FROM management.categories WHERE capture_id=:capture ORDER BY rowid LIMIT 200", orm.WithNamedArgs(params), orm.WithResult(&categories))
	if err != nil {
		return nil, err
	}
	for _, row := range categories {
		item := management.CompactCategory{Day: row.Day, ProfileID: row.ProfileID, Host: row.Host, Country: row.Country, Blocked: row.Blocked, Lists: []string{}}
		if err = json.Unmarshal([]byte(row.Lists), &item.Lists); err != nil {
			return nil, err
		}
		batch.Categories = append(batch.Categories, item)
	}
	if len(batch.Hourly) == 0 && len(batch.Destinations) == 0 && len(batch.Categories) == 0 {
		err = sqlitex.Execute(db.writeConn, "COMMIT", nil)
		return nil, err
	}
	body, err := management.MarshalCompactBatch(batch)
	if err != nil {
		return nil, err
	}
	if err = sqlitex.Execute(db.writeConn, "INSERT INTO management.outbox(capture_id,sequence,body) VALUES(:capture,:sequence,:body)", &sqlitex.ExecOptions{Named: map[string]any{":capture": capture.ID, ":sequence": batch.Sequence, ":body": body}}); err != nil {
		return nil, err
	}
	if err = sqlitex.Execute(db.writeConn, "UPDATE management.capture SET sequence=:sequence WHERE id=:capture", &sqlitex.ExecOptions{Named: map[string]any{":capture": capture.ID, ":sequence": batch.Sequence}}); err != nil {
		return nil, err
	}
	for _, stmt := range []string{
		"DELETE FROM management.hours WHERE rowid IN(SELECT rowid FROM management.hours WHERE capture_id=:capture ORDER BY hour LIMIT 24)",
		"DELETE FROM management.destinations WHERE rowid IN(SELECT rowid FROM management.destinations WHERE capture_id=:capture ORDER BY rowid LIMIT 200)",
		"DELETE FROM management.categories WHERE rowid IN(SELECT rowid FROM management.categories WHERE capture_id=:capture ORDER BY rowid LIMIT 200)",
	} {
		if err = orm.RunQuery(ctx, db.writeConn, stmt, orm.WithNamedArgs(params)); err != nil {
			return nil, err
		}
	}
	if err = sqlitex.Execute(db.writeConn, "COMMIT", nil); err != nil {
		return nil, err
	}
	return &management.CompactDelivery{StreamID: batch.StreamID, Sequence: batch.Sequence, Body: body}, nil
}

func (db *Database) AcknowledgeCompactSummary(ctx context.Context, deviceID, streamID string, sequence int64) error {
	if db.summaryErr != nil {
		return db.summaryErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	db.l.Lock()
	defer db.l.Unlock()
	capture, err := db.compactCapture(ctx, deviceID)
	if err != nil {
		return err
	}
	if capture.ID == 0 || capture.StreamID != streamID || capture.Sequence != sequence {
		return errors.New("compact acknowledgment does not match capture")
	}
	return sqlitex.Execute(db.writeConn, "DELETE FROM management.outbox WHERE capture_id=:capture AND sequence=:sequence", &sqlitex.ExecOptions{Named: map[string]any{":capture": capture.ID, ":sequence": sequence}})
}
