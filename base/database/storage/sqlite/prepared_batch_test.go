package sqlite

import (
	"fmt"
	"github.com/packettale/agents/base/database/record"
	"testing"
)

func TestPreparedBatchesRetainRemainderAndUpsertMetadata(t *testing.T) {
	for _, count := range []int{0, 1, 49, 50, 51, 1001} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			db, err := openSQLite("test", t.TempDir(), true)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Shutdown()
			for pass := 0; pass < 2; pass++ {
				put, errs := db.PutMany(false)
				for i := 0; i < count; i++ {
					r := &TestRecord{S: fmt.Sprintf("pass-%d", pass), I: i}
					r.SetKey(fmt.Sprintf("test:batch/%04d", i))
					r.UpdateMeta()
					r.Meta().Created = 123
					r.Meta().Modified = int64(456 + pass)
					put <- r
				}
				close(put)
				if err := <-errs; err != nil {
					t.Fatal(err)
				}
				for i := 0; i < count; i++ {
					got, err := db.Get(fmt.Sprintf("batch/%04d", i))
					if err != nil {
						t.Fatal(err)
					}
					value := &TestRecord{}
					if err := record.Unwrap(got, value); err != nil {
						t.Fatal(err)
					}
					if value.I != i || value.S != fmt.Sprintf("pass-%d", pass) || value.Meta().Modified != int64(456+pass) || value.Meta().Created != 123 {
						t.Fatalf("lost row or metadata at %d: %+v", i, value)
					}
				}
			}
		})
	}
}
