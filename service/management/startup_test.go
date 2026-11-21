package management

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/packettale/agents/base/config"
)

func startupOptions(t *testing.T) {
	t.Helper()
	recoveryOptions(t)
	for _, option := range []*config.Option{
		{Name: "Inbound", Description: "Startup test", Key: "filter/blockInbound", OptType: config.OptTypeBool, DefaultValue: true},
		{Name: "Intercept DNS", Description: "Startup test", Key: "filter/dnsQueryInterception", OptType: config.OptTypeBool, DefaultValue: true},
		{Name: "DNS listener", Description: "Startup test", Key: "dns/listenAddress", OptType: config.OptTypeString, DefaultValue: "localhost:53", RequiresRestart: true},
	} {
		if _, err := config.GetOption(option.Key); err != nil {
			if err := config.Register(option); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func startupPolicy() Policy {
	return Policy{Type: "policy", Revision: 1, LocalHistoryDays: 30,
		GlobalSettings: map[string]any{"filter/blockInbound": true, "filter/dnsQueryInterception": true},
		NetworkProfiles: []NetworkProfile{{ID: testNetworkID, Name: "Office", Enabled: true,
			CIDRs: []string{"198.18.0.0/15"}, GlobalSettings: map[string]any{
				"filter/blockInbound": false, "filter/dnsQueryInterception": false, "dns/listenAddress": "127.0.0.17:53",
			}}}}
}

func TestFreshInstallWaitsForValidPolicyBeforeNativeNetworking(t *testing.T) {
	startupOptions(t)
	c := New(t.TempDir(), nil)
	c.readNetwork = func() networkSnapshot {
		return networkSnapshot{addresses: []netip.Addr{netip.MustParseAddr("198.18.0.5")}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- c.StartEnforcement(ctx, func() error {
			if config.GetAsBool("filter/blockInbound", true)() || config.GetAsBool("filter/dnsQueryInterception", true)() {
				t.Error("factory/global policy reached native networking before the matching network policy")
			}
			if config.GetAsString("dns/listenAddress", "")() != "127.0.0.17:53" {
				t.Error("restart-only setting did not reach the first native startup")
			}
			if c.endpointReady() != nil {
				t.Error("reported ready before native startup completed")
			}
			close(started)
			return nil
		})
	}()
	invalid := startupPolicy()
	invalid.NetworkProfiles[0].CIDRs = []string{"invalid"}
	if err := c.installPolicy(ctx, invalid); err == nil {
		t.Fatal("invalid policy accepted")
	}
	select {
	case <-started:
		t.Fatal("native networking started before a valid policy arrived")
	case <-time.After(100 * time.Millisecond):
	}
	if err := c.installPolicy(ctx, startupPolicy()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	ready := c.endpointReady()
	if ready == nil || ready["network_profile_id"] != testNetworkID || ready["restart_required"] != false {
		t.Fatalf("first policy required a restart or selected the wrong network: %v", ready)
	}
}

func TestStartupRechecksNetworkBeforeEnforcement(t *testing.T) {
	startupOptions(t)
	c := New(t.TempDir(), nil)
	c.readNetwork = func() networkSnapshot { return networkSnapshot{} }
	if err := c.installPolicy(context.Background(), startupPolicy()); err != nil {
		t.Fatal(err)
	}
	c.readNetwork = func() networkSnapshot {
		return networkSnapshot{addresses: []netip.Addr{netip.MustParseAddr("198.18.0.9")}}
	}
	if err := c.StartEnforcement(context.Background(), func() error {
		if config.GetAsBool("filter/blockInbound", true)() || c.policyAcknowledgment(false)["network_profile_id"] != testNetworkID {
			t.Error("enforced an earlier network selection")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestStartupCanStopWhileWaitingAndDoesNotReportFailedNativeStartupReady(t *testing.T) {
	startupOptions(t)
	c := New(t.TempDir(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.StartEnforcement(ctx, func() error { t.Fatal("started after cancellation"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("startup did not cancel: %v", err)
	}
	if err := c.installPolicy(context.Background(), startupPolicy()); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("native startup failed")
	if err := c.StartEnforcement(context.Background(), func() error { return failure }); !errors.Is(err, failure) || c.endpointReady() != nil {
		t.Fatal("native startup failure was hidden or reported ready")
	}
}

func TestCachedPolicySelectsCurrentNetworkBeforeNativeStartup(t *testing.T) {
	startupOptions(t)
	c := New(t.TempDir(), nil)
	if err := writePrivateJSON(filepath.Join(c.dataDir, policyFile), startupPolicy()); err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	c.readNetwork = func() networkSnapshot {
		return networkSnapshot{addresses: []netip.Addr{netip.MustParseAddr("198.18.0.9")}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.StartEnforcement(ctx, func() error {
		if config.GetAsBool("filter/blockInbound", true)() {
			t.Error("cached policy did not select its matching network before startup")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
