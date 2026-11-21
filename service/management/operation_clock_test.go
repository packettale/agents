package management

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOperationClockBoundsTransitAndElapsedTime(t *testing.T) {
	server := time.Date(2026, 11, 13, 2, 0, 0, 0, time.UTC)
	for _, offset := range []time.Duration{-14 * time.Hour, 0, 14 * time.Hour} {
		started := time.Now().Add(offset)
		received := started.Add(2 * time.Second)
		clock, err := newOperationClock(server, started, received)
		if err != nil {
			t.Fatal(err)
		}
		got, valid := clock.at(received.Add(3 * time.Second))
		if !valid || !got.Equal(server.Add(5*time.Second)) {
			t.Fatalf("local clock affected reference: %v", got)
		}
	}
	now := time.Now()
	for _, test := range []struct{ stamp, start, end time.Time }{
		{time.Time{}, now, now}, {server, now, now.Add(-time.Second)}, {server, now, now.Add(76 * time.Second)},
	} {
		if _, err := newOperationClock(test.stamp, test.start, test.end); err == nil {
			t.Fatal("invalid/late reference accepted")
		}
	}
	if _, valid := (operationClock{}).at(now); valid {
		t.Fatal("missing session reference accepted")
	}
	clock, _ := newOperationClock(server, now, now)
	if _, valid := clock.at(now.Add(-time.Second)); valid {
		t.Fatal("negative elapsed time accepted")
	}
}

func TestOperationsUseSessionClockAndRejectDelayedDeadlines(t *testing.T) {
	for _, test := range []struct {
		name                           string
		offset, transit, age, deadline time.Duration
		missing, wantAccepted          bool
	}{
		{name: "endpoint behind server", offset: 12 * time.Hour, deadline: time.Minute, wantAccepted: true},
		{name: "endpoint ahead of server", offset: -12 * time.Hour, deadline: time.Minute, wantAccepted: true},
		{name: "expired in transit", transit: 10 * time.Second, deadline: 5 * time.Second},
		{name: "expired after receipt", age: 61 * time.Second, deadline: time.Minute},
		{name: "unbounded future", deadline: 3 * time.Minute},
		{name: "missing reference", deadline: time.Minute, missing: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := New(t.TempDir(), nil)
			c.SetServiceReady(true)
			var calls atomic.Int32
			done := make(chan struct{})
			c.SetOperationHandlers(OperationHandlers{ClearDNSCache: func(context.Context) error { calls.Add(1); close(done); return nil }})
			received := time.Now().Add(-test.age)
			server := received.Add(test.offset)
			clock, _ := newOperationClock(server, received.Add(-test.transit), received)
			if test.missing {
				clock = operationClock{}
			}
			var command map[string]any
			_ = json.Unmarshal(operationData(c, "clear_dns_cache"), &command)
			command["expires_at"] = server.Add(test.deadline)
			body, _ := json.Marshal(command)
			var status string
			err := c.handleOperation(context.Background(), clock, body, func(value any) error {
				state := value.(map[string]string)["status"]
				if state == "accepted" || state == "failed" {
					status = state
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if (status == "accepted") != test.wantAccepted {
				t.Fatalf("unexpected status %q", status)
			}
			if test.wantAccepted {
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("native action missing")
				}
			} else if calls.Load() != 0 {
				t.Fatal("rejected command executed")
			}
		})
	}
}

func TestControlReconnectCannotReusePreviousTimeReference(t *testing.T) {
	recoveryOptions(t)
	f := testChannelServer(t, http.NotFoundHandler())
	c := New(t.TempDir(), nil)
	c.state = f.identity(t, "clock-test-device", "clock-test-credential")
	c.SetServiceReady(true)
	var calls atomic.Int32
	c.SetOperationHandlers(OperationHandlers{ClearDNSCache: func(context.Context) error { calls.Add(1); return nil }})
	for _, stamp := range []any{time.Now().UTC().Format(time.RFC3339Nano), nil, "not-a-timestamp"} {
		f.Control = func(control *privateControl) {
			_, _, err := control.ReadMessage()
			if err != nil {
				return
			}
			message := map[string]any{"type": "policy", "revision": 1, "local_history_days": 90, "capabilities": []string{"endpoint-operations-v1"}}
			if stamp != nil {
				message["server_time"] = stamp
			}
			if control.WriteJSON(message) != nil {
				return
			}
			// Only a valid initial envelope may lead to policy/ready acknowledgments.
			if _, _, err = control.ReadMessage(); err != nil {
				return
			}
			if _, _, err = control.ReadMessage(); err != nil {
				return
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := c.connect(ctx, f.Config)
		cancel()
		if stamp == nil && (err == nil || !strings.Contains(err.Error(), "time reference")) {
			t.Fatalf("reused previous session clock: %v", err)
		}
		if stamp == "not-a-timestamp" && err == nil {
			t.Fatal("malformed reference accepted")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid session executed action")
	}
}

func TestSessionClockRejectsSuspendAndWallClockChanges(t *testing.T) {
	for _, test := range []struct {
		name            string
		monotonic, wall time.Duration
		want            time.Duration
		valid           bool
	}{
		{"normal elapsed", time.Minute, time.Minute, time.Minute, true},
		{"short suspend uses greater reading", time.Minute, 64 * time.Second, 64 * time.Second, true},
		{"small wall correction cannot extend deadline", time.Minute, 58 * time.Second, time.Minute, true},
		{"system slept for an hour", time.Second, time.Hour, 0, false},
		{"forward clock jump", time.Second, time.Minute, 0, false},
		{"backward clock jump", time.Minute, time.Second, 0, false},
		{"negative monotonic elapsed", -time.Second, time.Second, 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, valid := checkedElapsed(test.monotonic, test.wall)
			if got != test.want || valid != test.valid {
				t.Fatalf("got %v/%v want %v/%v", got, valid, test.want, test.valid)
			}
		})
	}
}
