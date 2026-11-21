package netquery

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/puddle/v2"
	"github.com/packettale/agents/service/netquery/orm"
	"zombiezen.com/go/sqlite"
)

func TestReadContextInterruptsSQLiteAndLeavesConnectionReusable(t *testing.T) {
	for _, batch := range []bool{false, true} {
		name := "query"
		if batch {
			name = "batch"
		}
		t.Run(name, func(t *testing.T) {
			// A separate emergency interrupt prevents a broken implementation
			// from hanging the suite. It is not the query's expected deadline.
			emergency := make(chan struct{})
			var emergencyFired atomic.Bool
			timer := time.AfterFunc(2*time.Second, func() {
				emergencyFired.Store(true)
				close(emergency)
			})
			defer timer.Stop()
			pool, err := puddle.NewPool(&puddle.Config[*sqlite.Conn]{
				MaxSize: 1,
				Constructor: func(context.Context) (*sqlite.Conn, error) {
					conn, err := sqlite.OpenConn(":memory:", 0)
					if err == nil {
						conn.SetInterrupt(emergency)
					}
					return conn, err
				},
				Destructor: func(conn *sqlite.Conn) { _ = conn.Close() },
			})
			if err != nil {
				t.Fatal(err)
			}
			defer pool.Close()
			db := &Database{readConnPool: pool}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			const expensive = `WITH RECURSIVE seq(n) AS
				(SELECT 0 UNION ALL SELECT n+1 FROM seq WHERE n<100000000) SELECT sum(n) FROM seq`
			started := time.Now()
			if batch {
				var first, slow []map[string]any
				err = db.ExecuteBatch(ctx, []BatchExecute{
					{SQL: "SELECT 1 AS value", Result: &first},
					{SQL: expensive, Result: &slow},
				})
			} else {
				err = db.Execute(ctx, expensive)
			}
			timer.Stop()
			t.Logf("read context: elapsed=%s, error=%v", time.Since(started), err)
			if emergencyFired.Load() || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("query ignored its context and needed emergency cleanup: %v", err)
			}
			borrowed, err := pool.Acquire(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			previous := borrowed.Value().SetInterrupt(nil)
			borrowed.Value().SetInterrupt(previous)
			borrowed.Release()
			if previous != emergency {
				t.Fatal("the previous interrupt channel was not restored before release")
			}
			var rows []struct {
				Value int `sqlite:"value"`
			}
			if err := db.Execute(context.Background(), "SELECT 1 AS value", orm.WithResult(&rows)); err != nil {
				t.Fatalf("cancelled context leaked into the pooled connection: %v", err)
			}
			if len(rows) != 1 || rows[0].Value != 1 {
				t.Fatalf("unexpected result after cancellation: %+v", rows)
			}
		})
	}
}
