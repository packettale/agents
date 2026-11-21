package management

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/packettale/agents/base/config"
)

const testNetworkID = "a5a63264-01cd-4dd2-a495-17c044c1c4a2"

func TestPolicyInstallSamplesNetworkUnderPolicyLock(t *testing.T) {
	recoveryOptions(t)
	c := New(t.TempDir(), nil)
	sampled := make(chan struct{})
	c.readNetwork = func() networkSnapshot {
		close(sampled)
		return networkSnapshot{addresses: []netip.Addr{netip.MustParseAddr("198.18.0.5")}}
	}
	p := Policy{Type: "policy", Revision: 2, LocalHistoryDays: 90, NetworkProfiles: []NetworkProfile{{ID: testNetworkID, Name: "Office", Enabled: true, CIDRs: []string{"198.18.0.0/15"}}}}
	c.policyMu.Lock()
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() { close(started); done <- c.installPolicy(context.Background(), p) }()
	<-started
	early := false
	select {
	case <-sampled:
		early = true
	case <-time.After(time.Second):
	}
	c.policyMu.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("policy install failed to resume")
	}
	if early {
		t.Fatal("stale network snapshot captured before policy serialization")
	}
	if c.policyAcknowledgment(true)["network_profile_id"] != testNetworkID {
		t.Fatal("current sampled profile did not apply")
	}
}

func TestNetworkPolicyMatchRequiresEveryConfiguredCriterion(t *testing.T) {
	policy := Policy{Revision: 3, LocalHistoryDays: 90, GlobalSettings: map[string]any{"filter/blockInbound": false},
		NetworkProfiles: []NetworkProfile{{ID: testNetworkID, Name: "Office", Enabled: true,
			CIDRs: []string{"10.20.0.0/16", "fd12:3456::/32"}, DNSSuffixes: []string{"office.example"},
			GlobalSettings: map[string]any{"filter/blockInbound": true}}}}
	for _, test := range []struct {
		name, ip, suffix string
		match            bool
	}{
		{"office", "10.20.1.5", "office.example", true},
		{"subdomain", "10.20.1.5", "branch.office.example.", true},
		{"ipv6", "fd12:3456::1", "OFFICE.EXAMPLE", true},
		{"remote", "192.168.1.5", "office.example", false},
		{"wrong suffix", "10.20.1.5", "fakeoffice.example", false},
		{"missing suffix", "10.20.1.5", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			effective, id := selectNetworkPolicy(policy, networkSnapshot{addresses: []netip.Addr{netip.MustParseAddr(test.ip)}, suffixes: []string{test.suffix}})
			if (id == testNetworkID) != test.match || effective.GlobalSettings["filter/blockInbound"] != test.match {
				t.Fatalf("id=%s policy=%v", id, effective.GlobalSettings)
			}
			if policy.GlobalSettings["filter/blockInbound"] != false {
				t.Fatal("selection mutated fallback policy")
			}
		})
	}
}

func TestNetworkPolicyPriorityDisabledAndFallback(t *testing.T) {
	first := NetworkProfile{ID: testNetworkID, Name: "VPN", Enabled: false, CIDRs: []string{"10.0.0.0/8"}, GlobalSettings: map[string]any{"filter/blockInbound": true}}
	second := first
	second.ID = "b5a63264-01cd-4dd2-a495-17c044c1c4a2"
	second.Enabled = true
	p := Policy{Revision: 1, LocalHistoryDays: 90, NetworkProfiles: []NetworkProfile{first, second}}
	s := networkSnapshot{addresses: []netip.Addr{netip.MustParseAddr("10.20.0.1")}}
	_, id := selectNetworkPolicy(p, s)
	if id != second.ID {
		t.Fatal("disabled first profile blocked later match")
	}
	p.NetworkProfiles[0].Enabled = true
	_, id = selectNetworkPolicy(p, s)
	if id != first.ID {
		t.Fatal("profile order was ignored")
	}
	effective, id := selectNetworkPolicy(p, networkSnapshot{})
	if id != "" || len(effective.GlobalSettings) != 0 {
		t.Fatal("unknown network did not use fallback")
	}
}

func TestInvalidNetworkProfileCannotReplaceCachedPolicy(t *testing.T) {
	recoveryOptions(t)
	c := New(t.TempDir(), nil)
	base := Policy{Type: "policy", Revision: 1, LocalHistoryDays: 90, MandatoryBlockDomains: []string{".blocked.example"}}
	if err := c.installPolicy(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(c.dataDir, policyFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []NetworkProfile{
		{ID: testNetworkID, Name: "Bad", Enabled: true, CIDRs: []string{"garbage"}},
		{ID: testNetworkID, Name: "Bad", Enabled: true, CIDRs: []string{"10.0.0.0/8"}, GlobalSettings: map[string]any{"core/apiKeys": []string{"secret"}}},
		{ID: testNetworkID, Name: "Empty", Enabled: true},
		{ID: testNetworkID, Name: "Bad suffix", Enabled: true, DNSSuffixes: []string{"*.example"}},
		{ID: "not-an-id", Name: "Bad ID", Enabled: true, CIDRs: []string{"10.0.0.0/8"}},
	} {
		invalid := base
		invalid.Revision = 2
		invalid.NetworkProfiles = []NetworkProfile{p}
		if err := c.installPolicy(context.Background(), invalid); err == nil {
			t.Fatalf("accepted invalid network profile %+v", p)
		}
		after, _ := os.ReadFile(filepath.Join(c.dataDir, policyFile))
		if string(before) != string(after) || !MandatoryBlockDomain("x.blocked.example") || !config.LocalWritesLocked() {
			t.Fatal("invalid network profile changed cache/protection")
		}
	}
}

func TestNetworkSwitchPreservesCachedBaseAndMandatoryProtection(t *testing.T) {
	recoveryOptions(t)
	const key = "filter/blockInbound"
	if _, err := config.GetOption(key); err != nil {
		if err := config.Register(&config.Option{Name: "Inbound", Description: "Network policy test", Key: key, OptType: config.OptTypeBool, DefaultValue: false}); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = config.SetManagedValue(key, nil) })
	c := New(t.TempDir(), nil)
	p := Policy{Type: "policy", Revision: 7, LocalHistoryDays: 90, MandatoryBlockDomains: []string{".blocked.example"}, GlobalSettings: map[string]any{key: false}, NetworkProfiles: []NetworkProfile{{ID: testNetworkID, Name: "Office", Enabled: true, CIDRs: []string{"198.18.0.0/15"}, GlobalSettings: map[string]any{key: true}}}}
	if err := c.installPolicy(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(c.dataDir, policyFile))
	c.policyMu.Lock()
	err := c.applyNetworkPolicyLocked(p, networkSnapshot{addresses: []netip.Addr{netip.MustParseAddr("198.18.0.5")}})
	c.policyMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if !config.GetAsBool(key, false)() || c.policyAcknowledgment(true)["network_profile_id"] != testNetworkID {
		t.Fatal("matched profile did not activate/report")
	}
	c.policyMu.Lock()
	err = c.applyNetworkPolicyLocked(p, networkSnapshot{})
	c.policyMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if config.GetAsBool(key, false)() || c.policyAcknowledgment(true)["network_profile_id"] != "" {
		t.Fatal("remote network did not restore/report fallback")
	}
	after, _ := os.ReadFile(filepath.Join(c.dataDir, policyFile))
	if string(after) != string(before) || !MandatoryBlockDomain("x.blocked.example") || !config.LocalWritesLocked() {
		t.Fatal("local network selection changed cache or mandatory protection")
	}
}
