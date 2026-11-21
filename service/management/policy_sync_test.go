package management

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/packettale/agents/base/config"
	"github.com/packettale/agents/service/mgr"
	"github.com/packettale/agents/service/profile"
)

func recoveryOptions(t *testing.T) {
	t.Helper()
	for _, option := range []*config.Option{
		{Name: "History enabled", Description: "Enable local history", Key: profile.CfgOptionEnableHistoryKey, OptType: config.OptTypeBool, DefaultValue: true},
		{Name: "History retention", Description: "Local retention days", Key: profile.CfgOptionKeepHistoryKey, OptType: config.OptTypeInt, DefaultValue: 30},
	} {
		if _, err := config.GetOption(option.Key); err != nil {
			if err := config.Register(option); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Cleanup(func() {
		_ = applyMandatoryPolicy(Policy{Revision: 1, LocalHistoryDays: 90})
		_ = config.SetManagedValue(profile.CfgOptionEnableHistoryKey, nil)
		_ = config.SetManagedValue(profile.CfgOptionKeepHistoryKey, nil)
		config.SetLocalWritesLocked(false)
	})
}

func recoveryClient(t *testing.T, server *httptest.Server) (*Client, Config) {
	t.Helper()
	dir := t.TempDir()
	f := testChannelServer(t, server.Config.Handler)
	f.Control = func(control *privateControl) { bridgeControlFixture(t, server, control) }
	provision := f.Config
	if err := writePrivateJSON(filepath.Join(dir, configFile), provision); err != nil {
		t.Fatal(err)
	}
	c := New(dir, nil)
	if err := c.saveIdentity(f.identity(t, "device-1", "device-secret")); err != nil {
		t.Fatal(err)
	}
	cfg, err := c.loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if err = c.loadState(); err != nil {
		t.Fatal(err)
	}
	return c, cfg
}

func runRecovery(ctx context.Context, c *Client, cfg Config) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = c.mgr.Do("test policy recovery", func(w *mgr.WorkerCtx) error {
			c.run(ctx, cfg, w)
			return nil
		})
	}()
	return done
}

func TestRejectedWebSocketRecoversPolicyAndAcknowledgesOverHTTPS(t *testing.T) { //nolint:paralleltest
	recoveryOptions(t)
	ack := make(chan map[string]any, 1)
	var attempts atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer device-secret" {
			t.Error("recovery did not use enrolled device authentication")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/ws/device/" {
			attempts.Add(1)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.URL.Path != "/api/v1/device/policy/" {
			t.Errorf("unexpected recovery path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(Policy{Type: "policy", Revision: 8, LocalHistoryDays: 30,
				MandatoryBlockDomains: []string{".blocked.example"}, Capabilities: []string{"applications-v1"}})
			return
		}
		var report map[string]any
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = fmt.Fprint(w, `{"accepted":true,"revision":8}`)
		ack <- report
	}))
	defer server.Close()
	c, cfg := recoveryClient(t, server)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := runRecovery(ctx, c, cfg)
	select {
	case report := <-ack:
		if len(report) != 2 || report["revision"] != float64(8) || report["version"] == nil {
			t.Errorf("invalid applied-policy report: %#v", report)
		}
	case <-ctx.Done():
		t.Error("no HTTPS policy acknowledgment after WebSocket rejection")
	}
	cancel()
	<-done
	if attempts.Load() == 0 || !MandatoryBlockDomain("sub.blocked.example") || MandatoryHistoryDays() != 30 {
		t.Fatal("HTTPS policy did not reach the cached firewall state")
	}
	var stored Policy
	data, err := os.ReadFile(filepath.Join(c.dataDir, policyFile))
	if err != nil || json.Unmarshal(data, &stored) != nil || stored.Revision != 8 {
		t.Fatal("HTTPS policy was not persisted for offline restart")
	}
	if !config.LocalWritesLocked() || !c.applicationCatalogueEnabled.Load() {
		t.Fatal("HTTPS policy bypassed managed lock or capability application")
	}
}

func TestHealthyWebSocketDoesNotPollHTTPS(t *testing.T) { //nolint:paralleltest
	var polls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ws/device/" {
			polls.Add(1)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteJSON(map[string]string{"type": "pong"})
		<-ctx.Done()
	}))
	defer server.Close()
	c, cfg := recoveryClient(t, server)
	done := runRecovery(ctx, c, cfg)
	time.Sleep(1100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("management cancellation did not close healthy WebSocket")
	}
	if polls.Load() != 0 {
		t.Fatal("healthy WebSocket caused unnecessary HTTPS recovery polling")
	}
}

func TestPolicyRecoveryRejectsInvalidResponsesWithoutReplacingCache(t *testing.T) { //nolint:paralleltest
	recoveryOptions(t)
	good := Policy{Type: "policy", Revision: 3, LocalHistoryDays: 90,
		MandatoryBlockDomains: []string{".cached.example"}}
	for _, test := range []struct {
		name   string
		status int
		body   string
	}{
		{"unauthorized", 401, `{}`},
		{"server unavailable", 503, `{}`},
		{"wrong type", 200, `{"type":"query","revision":4,"local_history_days":30}`},
		{"invalid setting", 200, `{"type":"policy","revision":4,"local_history_days":30,"global_settings":{"core/apiKeys":["key"]}}`},
		{"invalid revision", 200, `{"type":"policy","revision":0,"local_history_days":30}`},
		{"trailing document", 200, `{"type":"policy","revision":4,"local_history_days":30} {}`},
		{"oversized", 200, `{"type":"policy","revision":4,"local_history_days":30}` + strings.Repeat(" ", 65536)},
	} {
		t.Run(test.name, func(t *testing.T) {
			var posts atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					posts.Add(1)
				}
				w.WriteHeader(test.status)
				_, _ = fmt.Fprint(w, test.body)
			}))
			defer server.Close()
			c, cfg := recoveryClient(t, server)
			if err := c.installPolicy(context.Background(), good); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(filepath.Join(c.dataDir, policyFile))
			if err := c.recoverPolicy(context.Background(), cfg); err == nil {
				t.Fatal("invalid policy response accepted")
			}
			after, _ := os.ReadFile(filepath.Join(c.dataDir, policyFile))
			if string(before) != string(after) || !MandatoryBlockDomain("cached.example") || posts.Load() != 0 {
				t.Fatal("invalid policy replaced cached enforcement or was acknowledged")
			}
		})
	}
}

func TestPolicyRecoveryRetriesAcknowledgmentWithoutRewritingCache(t *testing.T) { //nolint:paralleltest
	recoveryOptions(t)
	var posts atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = fmt.Fprint(w, `{"type":"policy","revision":4,"local_history_days":30}`)
			return
		}
		if posts.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = fmt.Fprint(w, `{"accepted":true,"revision":4}`)
	}))
	defer server.Close()
	c, cfg := recoveryClient(t, server)
	if err := c.recoverPolicy(context.Background(), cfg); err == nil {
		t.Fatal("failed acknowledgment was reported as success")
	}
	cache := filepath.Join(c.dataDir, policyFile)
	oldTime := time.Unix(1600000000, 0)
	if err := os.Chtimes(cache, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	if err := c.recoverPolicy(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	stat, err := os.Stat(cache)
	if err != nil || !stat.ModTime().Equal(oldTime) || posts.Load() != 2 {
		t.Fatal("acknowledgment retry rewrote the offline cache or did not retry")
	}
}

func TestPolicyRecoveryRequiresExactSuccessfulAcknowledgment(t *testing.T) { //nolint:paralleltest
	recoveryOptions(t)
	for _, body := range []string{`{}`, `{"accepted":false,"revision":4}`,
		`{"accepted":true,"revision":3}`, `{"accepted":true,"revision":4} {}`,
		`{"accepted":true,"revision":4}` + strings.Repeat(" ", 4096)} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				_, _ = fmt.Fprint(w, `{"type":"policy","revision":4,"local_history_days":30}`)
				return
			}
			w.WriteHeader(http.StatusAccepted)
			_, _ = fmt.Fprint(w, body)
		}))
		c, cfg := recoveryClient(t, server)
		err := c.recoverPolicy(context.Background(), cfg)
		server.Close()
		if err == nil {
			t.Fatalf("invalid acknowledgment accepted: %.80s", body)
		}
	}
}

func TestPolicyRecoveryDoesNotFollowCredentialRedirectsOrTrustAnotherCA(t *testing.T) { //nolint:paralleltest
	var redirected atomic.Bool
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Store(true)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	c, cfg := recoveryClient(t, server)
	if err := c.recoverPolicy(context.Background(), cfg); err == nil || redirected.Load() {
		t.Fatal("policy redirect was followed with device authentication")
	}
	// The standard client has no lab CA; recovery must retain TLS verification.
	c.httpClient = &http.Client{Timeout: time.Second}
	if err := c.recoverPolicy(context.Background(), cfg); err == nil {
		t.Fatal("policy download accepted an untrusted TLS certificate")
	}
}

func TestPolicyRecoveryCancelsInFlightHTTPRequest(t *testing.T) { //nolint:paralleltest
	received := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(received)
		<-r.Context().Done()
	}))
	defer server.Close()
	c, cfg := recoveryClient(t, server)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.recoverPolicy(ctx, cfg) }()
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("policy request did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled policy request reported success")
		}
	case <-time.After(time.Second):
		t.Fatal("policy request ignored management shutdown")
	}
}
