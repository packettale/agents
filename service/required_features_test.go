package service

import (
	"context"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/packettale/agents/base/config"
	"github.com/packettale/agents/service/firewall"
	"github.com/packettale/agents/service/network"
	"github.com/packettale/agents/service/network/packet"
	"github.com/packettale/agents/service/profile"
)

// Constructors are process singletons. This fixture exercises the real profile,
// recording and firewall modules with temporary databases and synthetic traffic.
// It does not start packet interception or change the host network.
func TestRequiredRecordingAndFirewallPolicies(t *testing.T) {
	if os.Getenv("PACKETTALE_REQUIRED_FEATURES_FIXTURE") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestRequiredRecordingAndFirewallPolicies$", "-test.timeout=45s")
		cmd.Env = append(os.Environ(), "PACKETTALE_REQUIRED_FEATURES_FIXTURE=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("required-feature fixture failed: %v: %s", err, output)
		}
		return
	}
	instance, err := New(&ServiceConfig{BinDir: t.TempDir(), DataDir: t.TempDir(), LogToStdout: true})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.cancelCtx()
	defer instance.cancelShutdownCtx()
	defer instance.netquery.Store.Close()
	if err = instance.database.Start(); err != nil {
		t.Fatal(err)
	}
	defer instance.database.Stop()
	if err = instance.config.Start(); err != nil {
		t.Fatal(err)
	}
	defer instance.config.Manager().Cancel()
	if err = config.SetManagedValue("history/enable", true); err != nil {
		t.Fatal(err)
	}
	if err = instance.profile.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { instance.profile.Manager().Cancel(); instance.profile.Manager().WaitForWorkers(time.Second) }()
	ctx := context.Background()
	conn, err := network.NewConnectionFromExternalDNSRequest(ctx, "example.test.", nil, "scope-test", net.ParseIP("192.0.2.18"))
	if err != nil {
		t.Fatal(err)
	}
	if !conn.HistoryEnabled || !conn.BandwidthEnabled || conn.ProcessContext.Profile == "" {
		t.Fatalf("required local recording/attribution lost: history=%v bandwidth=%v profile=%s", conn.HistoryEnabled, conn.BandwidthEnabled, conn.ProcessContext.Profile)
	}
	scoped := conn.Process().Profile().LocalProfile().ScopedID()
	if err = profile.SetManagedApplicationRules(map[string]map[string]any{scoped: {"history/enable": false, "splittun/use": true, "splittun/networkInterface": "test-adapter", "splittun/usagePolicy": []string{"+ example.test"}}}); err != nil {
		t.Fatal(err)
	}
	defer profile.SetManagedApplicationRules(nil)
	if !conn.Process().Profile().UseSplitTun() || conn.Process().Profile().SplitTunInterface() != "test-adapter" {
		t.Fatal("managed split-tunnel settings lost")
	}
	if err = conn.UpdateFeatures(); err != nil {
		t.Fatal(err)
	}
	if conn.HistoryEnabled || !conn.BandwidthEnabled {
		t.Fatal("recording settings no longer respected")
	}
	for _, scenario := range []struct {
		name, action string
		rules        []string
		split        bool
		want         network.Verdict
	}{
		{"default allow", "permit", nil, false, network.VerdictAccept},
		{"default block", "block", nil, false, network.VerdictBlock},
		{"destination block", "permit", []string{"- 198.51.100.18"}, false, network.VerdictBlock},
		{"destination allow", "block", []string{"+ 198.51.100.18"}, false, network.VerdictAccept},
		{"split cannot bypass block", "permit", []string{"- 198.51.100.18"}, true, network.VerdictBlock},
	} {
		settings := map[string]any{"filter/defaultAction": scenario.action, "filter/endpoints": scenario.rules, "filter/disableAutoPermit": true, "splittun/use": scenario.split}
		if settings["filter/endpoints"] == nil {
			settings["filter/endpoints"] = []string{}
		}
		if err = profile.SetManagedApplicationRules(map[string]map[string]any{scoped: settings}); err != nil {
			t.Fatal(err)
		}
		sample, err := network.NewConnectionFromExternalDNSRequest(ctx, "example.test.", nil, scenario.name, net.ParseIP("192.0.2.18"))
		if err != nil {
			t.Fatal(err)
		}
		sample.Type = network.IPConnection
		sample.IPProtocol = packet.TCP
		sample.Entity.Protocol = uint8(packet.TCP)
		sample.Entity.IP = net.ParseIP("198.51.100.18")
		sample.Entity.Port = 443
		sample.Ended = 0
		sample.Lock()
		firewall.FilterConnection(ctx, sample, nil, true, true)
		actual := sample.Verdict
		reason := sample.Reason.Msg
		sample.Unlock()
		if actual != scenario.want {
			t.Errorf("%s: verdict=%v want=%v reason=%s", scenario.name, actual, scenario.want, reason)
		}
	}

	// A listener conflict must not turn an otherwise permitted DNS request into
	// a bypass block; transport and address-family readiness remain independent.
	t.Cleanup(func() {
		firewall.SetNameserverReadyMatcher(func(packet.IPVersion, packet.IPProtocol) bool { return false })
	})
	for _, scenario := range []struct {
		name             string
		version          packet.IPVersion
		protocol         packet.IPProtocol
		port             uint16
		ready            bool
		blockDestination bool
		want             network.Verdict
	}{
		{"UDP4 listener conflict", packet.IPv4, packet.UDP, 53, false, false, network.VerdictAccept},
		{"TCP4 listener conflict", packet.IPv4, packet.TCP, 53, false, false, network.VerdictAccept},
		{"UDP6 listener conflict", packet.IPv6, packet.UDP, 53, false, false, network.VerdictAccept},
		{"TCP6 listener conflict", packet.IPv6, packet.TCP, 53, false, false, network.VerdictAccept},
		{"healthy UDP keeps bypass prevention", packet.IPv4, packet.UDP, 53, true, false, network.VerdictBlock},
		{"healthy TCP keeps bypass prevention", packet.IPv4, packet.TCP, 53, true, false, network.VerdictBlock},
		{"DNS conflict preserves destination block", packet.IPv4, packet.UDP, 53, false, true, network.VerdictBlock},
		{"DNS conflict preserves encrypted DNS block", packet.IPv4, packet.TCP, 853, false, false, network.VerdictBlock},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			firewall.SetNameserverReadyMatcher(func(v packet.IPVersion, p packet.IPProtocol) bool {
				return scenario.ready && v == scenario.version && p == scenario.protocol
			})
			rules := []string{}
			if scenario.blockDestination {
				rules = []string{"- 198.51.100.18"}
			}
			if err := profile.SetManagedApplicationRules(map[string]map[string]any{scoped: {
				"filter/defaultAction": "permit", "filter/endpoints": rules,
				"filter/disableAutoPermit": true, "filter/preventBypassing": true,
				"splittun/use": false,
			}}); err != nil {
				t.Fatal(err)
			}
			sample, err := network.NewConnectionFromExternalDNSRequest(ctx, "example.test.", nil, scenario.name, net.ParseIP("192.0.2.18"))
			if err != nil {
				t.Fatal(err)
			}
			sample.Type = network.IPConnection
			sample.IPVersion = scenario.version
			sample.IPProtocol = scenario.protocol
			sample.Entity.Protocol = uint8(scenario.protocol)
			sample.Entity.IP = net.ParseIP("198.51.100.18")
			sample.Entity.Port = scenario.port
			sample.Ended = 0
			sample.Lock()
			firewall.FilterConnection(ctx, sample, nil, true, true)
			actual, reason := sample.Verdict, sample.Reason.Msg
			sample.Unlock()
			if actual != scenario.want {
				t.Errorf("verdict=%v want=%v reason=%s", actual, scenario.want, reason)
			}
			if !scenario.ready && !scenario.blockDestination && scenario.protocol == packet.UDP && scenario.port == 53 && !sample.Inspecting {
				t.Error("fallback UDP DNS must still undergo DNS packet validation")
			}
		})
	}

}
