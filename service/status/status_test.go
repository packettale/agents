package status

import (
	"github.com/packettale/agents/service/mgr"
	"testing"
)

func TestStatusReadPreservesSeverityWithoutLoggingErrors(t *testing.T) {
	// A read must not require a logger or report a warning as a new error.
	s := &Status{states: map[string]mgr.StateUpdate{
		"filterlists": {Module: "filterlists", States: []mgr.State{{ID: "initializing", Type: mgr.StateTypeWarning}}},
	}}
	for range 2 {
		got := s.buildSystemStatus()
		if got.WorstState.Type != mgr.StateTypeWarning {
			t.Fatal("incorrect worst severity")
		}
		got.Modules[0].States[0].Type = mgr.StateTypeError
	}
}
