package management

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/packettale/agents/base/config"
)

func testOperationClock() operationClock {
	now := time.Now()
	clock, _ := newOperationClock(now, now, now)
	return clock
}

func operationData(c *Client, action string) []byte {
	data, _ := json.Marshal(map[string]any{"type": "endpoint_operation", "operation_id": uuid.NewString(),
		"action": action, "expected_instance_id": c.instanceID, "expires_at": time.Now().Add(time.Minute).UTC()})
	return data
}

func TestEndpointOperationIsAcknowledgedBeforeNativeAction(t *testing.T) {
	c := New(t.TempDir(), nil)
	c.SetServiceReady(true)
	var calls atomic.Int32
	var accepted atomic.Bool
	done := make(chan struct{})
	c.SetOperationHandlers(OperationHandlers{ClearDNSCache: func(context.Context) error {
		if !accepted.Load() {
			t.Error("native action ran before accepted status was sent")
		}
		calls.Add(1)
		return nil
	}})
	data := operationData(c, "clear_dns_cache")
	write := func(message any) error {
		status := message.(map[string]string)["status"]
		if status == "accepted" {
			accepted.Store(true)
		}
		if status == "completed" {
			close(done)
		}
		return nil
	}
	if err := c.handleOperation(context.Background(), testOperationClock(), data, write); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("operation did not complete")
	}
	if err := c.handleOperation(context.Background(), testOperationClock(), data, func(any) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("duplicate operation ran twice")
	}
}

func TestEndpointOperationRejectsStaleUnknownExpiredAndBusy(t *testing.T) {
	c := New(t.TempDir(), nil)
	c.SetServiceReady(true)
	var calls atomic.Int32
	c.SetOperationHandlers(OperationHandlers{Restart: func(context.Context) error { calls.Add(1); return nil }})
	for _, test := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"stale", func(m map[string]any) { m["expected_instance_id"] = uuid.NewString() }},
		{"expired", func(m map[string]any) { m["expires_at"] = time.Now().Add(-time.Minute).Format(time.RFC3339) }},
		{"unknown", func(m map[string]any) { m["action"] = "shell" }},
		{"arguments", func(m map[string]any) { m["command"] = "anything" }},
		{"invalid identifier", func(m map[string]any) { m["operation_id"] = "not-uuid" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var m map[string]any
			_ = json.Unmarshal(operationData(c, "restart_service"), &m)
			test.change(m)
			data, _ := json.Marshal(m)
			_ = c.handleOperation(context.Background(), testOperationClock(), data, func(any) error { return nil })
		})
	}
	c.updateBusy.Store(true)
	_ = c.handleOperation(context.Background(), testOperationClock(), operationData(c, "restart_service"), func(any) error { return nil })
	time.Sleep(10 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatal("rejected operation invoked native callback")
	}
}

func TestEndpointOperationDoesNotExecuteAfterFailedAcknowledgment(t *testing.T) {
	c := New(t.TempDir(), nil)
	c.SetServiceReady(true)
	var calls atomic.Int32
	c.SetOperationHandlers(OperationHandlers{Restart: func(context.Context) error { calls.Add(1); return nil }})
	data := operationData(c, "restart_service")
	if err := c.handleOperation(context.Background(), testOperationClock(), data, func(any) error { return errors.New("disconnected") }); err == nil {
		t.Fatal("failed acknowledgment was ignored")
	}
	_ = c.handleOperation(context.Background(), testOperationClock(), data, func(any) error { return nil })
	time.Sleep(10 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatal("unacknowledged or replayed operation executed")
	}
	if c.updateBusy.Load() {
		t.Fatal("failed delivery leaked operation lock")
	}
}

func TestManagedRestartRequirementTracksTheRunningConfiguration(t *testing.T) {
	key := "enterprise-test/restart-setting"
	if _, err := config.GetOption(key); err != nil {
		if err := config.Register(&config.Option{Name: "DNS listen", Description: "Test listen address", Key: key,
			OptType: config.OptTypeString, DefaultValue: "localhost:53", RequiresRestart: true}); err != nil {
			t.Fatal(err)
		}
	}
	c := New(t.TempDir(), nil)
	c.SetServiceReady(true)
	c.captureRestartBaseline()
	if err := config.SetManagedValue(key, "127.0.0.17:53"); err != nil {
		t.Fatal(err)
	}
	defer config.SetManagedValue(key, nil) //nolint:errcheck
	if c.endpointReady()["restart_required"] != true {
		t.Fatal("managed restart-only setting reported fully applied")
	}
	if err := config.SetManagedValue(key, nil); err != nil {
		t.Fatal(err)
	}
	if c.endpointReady()["restart_required"] != false {
		t.Fatal("restoring the running value retained a false restart requirement")
	}
}

func TestEndpointOperationsUseTheAuthenticatedTLSWebSocket(t *testing.T) {
	recoveryOptions(t)
	received := make(chan []map[string]any, 1)
	upgrader := websocket.Upgrader{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer device-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		if err := conn.WriteJSON(Policy{Type: "policy", Revision: 1, LocalHistoryDays: 90, Capabilities: []string{"endpoint-operations-v1"}}); err != nil {
			return
		}
		var transcript []map[string]any
		for range 2 {
			var message map[string]any
			if err := conn.ReadJSON(&message); err != nil {
				t.Error(err)
				return
			}
			transcript = append(transcript, message)
		}
		if transcript[0]["type"] != "policy_applied" || transcript[1]["type"] != "endpoint_ready" {
			t.Errorf("missing policy/ready handshake: %v", transcript)
			return
		}
		command := map[string]any{"type": "endpoint_operation", "operation_id": uuid.NewString(), "action": "clear_dns_cache",
			"expected_instance_id": transcript[1]["instance_id"], "expires_at": time.Now().Add(time.Minute).UTC()}
		if err := conn.WriteJSON(command); err != nil {
			t.Error(err)
			return
		}
		for range 2 {
			var message map[string]any
			if err := conn.ReadJSON(&message); err != nil {
				t.Error(err)
				return
			}
			transcript = append(transcript, message)
		}
		received <- transcript
	}))
	defer server.Close()
	c, cfg := recoveryClient(t, server)
	c.SetServiceReady(true)
	var calls atomic.Int32
	c.SetOperationHandlers(OperationHandlers{ClearDNSCache: func(context.Context) error { calls.Add(1); return nil }})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = c.connect(ctx, cfg)
	select {
	case messages := <-received:
		if messages[2]["status"] != "accepted" || messages[3]["status"] != "completed" {
			t.Fatalf("incorrect operation status %v", messages)
		}
		if messages[1]["instance_id"] != c.instanceID || calls.Load() != 1 {
			t.Fatal("wrong process identity or callback count")
		}
	case <-ctx.Done():
		t.Fatal("authenticated operation exchange did not finish")
	}
}

func TestEndpointReadinessWaitsForNativeServiceStartup(t *testing.T) {
	c := New(t.TempDir(), nil)
	if c.endpointReady() != nil {
		t.Fatal("management advertised a ready process before native services started")
	}
	var calls atomic.Int32
	c.SetOperationHandlers(OperationHandlers{ClearDNSCache: func(context.Context) error { calls.Add(1); return nil }})
	_ = c.handleOperation(context.Background(), testOperationClock(), operationData(c, "clear_dns_cache"), func(any) error { return nil })
	time.Sleep(10 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatal("native action ran before service startup")
	}
}

func TestNextQueuedOperationCanStartFromCompletionAcknowledgment(t *testing.T) {
	c := New(t.TempDir(), nil)
	c.SetServiceReady(true)
	var calls atomic.Int32
	c.SetOperationHandlers(OperationHandlers{ClearDNSCache: func(context.Context) error { calls.Add(1); return nil }})
	completed := make(chan struct{})
	var count atomic.Int32
	var write func(any) error
	write = func(value any) error {
		state := value.(map[string]string)["status"]
		if state == "failed" {
			t.Error("next queued operation was rejected as busy")
			close(completed)
			return nil
		}
		if state == "completed" {
			if count.Add(1) == 1 {
				return c.handleOperation(context.Background(), testOperationClock(), operationData(c, "clear_dns_cache"), write)
			}
			close(completed)
		}
		return nil
	}
	if err := c.handleOperation(context.Background(), testOperationClock(), operationData(c, "clear_dns_cache"), write); err != nil {
		t.Fatal(err)
	}
	select {
	case <-completed:
	case <-time.After(time.Second):
		t.Fatal("queued operation did not finish")
	}
	if calls.Load() != 2 {
		t.Fatalf("completed %d native actions, want2", calls.Load())
	}
}
