//go:build !server

package netenv

import (
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

func TestResolvedRequiredSecurityKeepsNamespaceFenced(t *testing.T) {
	for _, requirement := range []struct {
		name, dnssec, tls string
		blocked           bool
	}{
		{"required-dnssec", "yes", "no", true},
		{"required-tls", "no", "yes", true},
		{"optional-security", "allow-downgrade", "opportunistic", false},
	} {
		t.Run(requirement.name, func(t *testing.T) {
			properties := map[string]dbus.Variant{
				"DNS":     dbus.MakeVariant([]resolvedDNS{{Link: 0, Family: 2, Address: []byte{192, 0, 2, 53}}}),
				"Domains": dbus.MakeVariant([]resolvedDomain{{Link: 0, Domain: "private.policy-fixture.com", RouteOnly: true}}),
				"DNSSEC":  dbus.MakeVariant(requirement.dnssec), "DNSOverTLS": dbus.MakeVariant(requirement.tls),
			}
			configuration, err := resolvedDNSConfiguration(properties)
			if err != nil {
				t.Fatal(err)
			}
			foundRoot := false
			for _, rule := range configuration.Rules {
				if rule.Blocked != requirement.blocked {
					t.Fatalf("OS security requirement was relaxed: %+v", rule)
				}
				foundRoot = foundRoot || rule.Namespace == "."
			}
			if requirement.blocked && !foundRoot {
				t.Fatal("required security on a global upstream lost its default-route fence")
			}
		})
	}
}

func TestResolvedLinkSecurityDoesNotOverrideOtherLinks(t *testing.T) {
	properties := map[string]dbus.Variant{
		"DNS": dbus.MakeVariant([]resolvedDNS{
			{Link: 7, Family: 2, Address: []byte{10, 20, 0, 53}},
			{Link: 0, Family: 2, Address: []byte{192, 0, 2, 53}},
		}),
		"Domains": dbus.MakeVariant([]resolvedDomain{{Link: 7, Domain: "private.policy-fixture.com", RouteOnly: true}}),
		"DNSSEC":  dbus.MakeVariant("no"), "DNSOverTLS": dbus.MakeVariant("no"),
	}
	link := map[string]dbus.Variant{"DNSSEC": dbus.MakeVariant("no"), "DNSOverTLS": dbus.MakeVariant("yes")}
	configuration, err := resolvedDNSConfigurationWithPolicies(properties, map[int32]bool{7: false}, map[int32]map[string]dbus.Variant{7: link})
	if err != nil {
		t.Fatal(err)
	}
	if len(configuration.Rules) != 1 || !configuration.Rules[0].Blocked || configuration.Rules[0].Namespace != "private.policy-fixture.com." {
		t.Fatalf("required link security escaped its namespace: %+v", configuration.Rules)
	}
	if !configuration.Nameservers[0].ScopeOnly || configuration.Nameservers[1].ScopeOnly {
		t.Fatal("required TLS upstream entered global fallback or blocked another link")
	}
	properties["DNSSEC"] = dbus.MakeVariant("yes")
	link["DNSOverTLS"] = dbus.MakeVariant("no")
	configuration, err = resolvedDNSConfigurationWithPolicies(properties, map[int32]bool{7: false}, map[int32]map[string]dbus.Variant{7: link})
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range configuration.Rules {
		if rule.Namespace == "private.policy-fixture.com." && rule.Blocked {
			t.Fatal("effective link override was replaced with the global security mode")
		}
	}
}

func TestResolvedUnknownSecurityMetadataIsRejected(t *testing.T) {
	for _, value := range []any{nil, "", "unexpected", true} {
		properties := map[string]dbus.Variant{"DNSSEC": dbus.MakeVariant("no")}
		if value != nil {
			properties["DNSOverTLS"] = dbus.MakeVariant(value)
		}
		if err := validateResolvedSecurityProperties(properties); err == nil {
			t.Errorf("accepted unknown TLS metadata: %v", value)
		}
	}
}

func TestResolvedCustomPortDoesNotSilentlyUsePort53(t *testing.T) {
	properties := map[string]dbus.Variant{
		"DNS":     dbus.MakeVariant([]resolvedDNS{{Link: 7, Family: 2, Address: []byte{10, 20, 0, 53}}}),
		"DNSEx":   dbus.MakeVariant([][]any{{int32(7), int32(2), []byte{10, 20, 0, 53}, uint16(1053), ""}}),
		"Domains": dbus.MakeVariant([]resolvedDomain{{Link: 7, Domain: "private.policy-fixture.com", RouteOnly: true}}),
	}
	configuration, err := resolvedDNSConfigurationWithDefaultRoutes(properties, map[int32]bool{7: true})
	if err != nil {
		t.Fatal(err)
	}
	root := false
	for _, rule := range configuration.Rules {
		if !rule.Blocked {
			t.Fatalf("custom-port route downgraded to port 53: %+v", rule)
		}
		root = root || rule.Namespace == "."
	}
	if !root {
		t.Fatal("unsupported default-route transport lost its fence")
	}
}

func TestResolvedNameserversPreservesLinkScopes(t *testing.T) {
	// These are the decoded a(iiay) / a(isb) shapes, not production structs.
	properties := map[string]dbus.Variant{
		"DNS": dbus.MakeVariant([][]any{
			{int32(2), int32(2), []byte{10, 20, 0, 53}},
			{int32(7), int32(10), []byte(net.ParseIP("fd00::53").To16())},
			{int32(0), int32(2), []byte{9, 9, 9, 9}},
			{int32(2), int32(2), []byte{127, 0, 0, 53}},
			{int32(2), int32(2), []byte{0, 0, 0, 0}},
			{int32(2), int32(2), []byte{224, 0, 0, 1}},
			{int32(2), int32(2), []byte{10}},
			{int32(2), int32(999), []byte{10, 0, 0, 53}},
			{int32(2), int32(10), []byte(net.ParseIP("fe80::53").To16())},
		}),
		"Domains": dbus.MakeVariant([][]any{
			{int32(2), "corp.example", false},
			{int32(7), "vpn.example", true},
			{int32(7), ".", true},
			{int32(0), "global.example", false},
		}),
	}
	servers, err := resolvedNameservers(properties)
	if err != nil || len(servers) != 3 {
		t.Fatalf("servers=%v error=%v", servers, err)
	}
	for i, want := range []struct {
		ip     string
		search []string
	}{
		{"10.20.0.53", []string{"corp.example"}},
		{"fd00::53", []string{"vpn.example"}},
		{"9.9.9.9", []string{"global.example"}},
	} {
		if servers[i].IP.String() != want.ip || !reflect.DeepEqual(servers[i].Search, want.search) {
			t.Errorf("server[%d]=%v, want %+v", i, servers[i], want)
		}
	}
}

func TestResolvedDuplicateAddressKeepsEveryLinkDomain(t *testing.T) {
	properties := map[string]dbus.Variant{
		"DNS": dbus.MakeVariant([][]any{
			{int32(2), int32(2), []byte{10, 0, 0, 53}},
			{int32(7), int32(2), []byte{10, 0, 0, 53}},
		}),
		"Domains": dbus.MakeVariant([][]any{
			{int32(2), "corp.example", false},
			{int32(7), "branch.example", true},
		}),
	}
	servers, err := resolvedNameservers(properties)
	if err != nil {
		t.Fatal(err)
	}
	servers = addNameservers(nil, servers)
	if len(servers) != 1 || !reflect.DeepEqual(servers[0].Search, []string{"corp.example", "branch.example"}) {
		t.Fatalf("lost link domains when aggregating: %v", servers)
	}
}

func TestFailedDNSDiscoverySchedulesOneRefresh(t *testing.T) {
	sub := module.EventNetworkChange.Subscribe(t.Name(), 2)
	defer sub.Cancel()
	flag := GetNetworkChangedFlag()
	flag.Refresh()
	RetryDNSDiscoveryAfter(10 * time.Millisecond)
	RetryDNSDiscoveryAfter(10 * time.Millisecond)
	select {
	case <-sub.Events():
		if !flag.IsSet() {
			t.Fatal("resolver's network cache not invalidated")
		}
	case <-time.After(time.Second):
		t.Fatal("failed discovery never triggers resolver reload")
	}
	select {
	case <-sub.Events():
		t.Fatal("retry was not coalesced")
	case <-time.After(30 * time.Millisecond):
	}
}

func TestResolvedSystemBusDiscovery(t *testing.T) {
	if os.Getenv("PACKETTALE_TEST_RESOLVED") != "1" {
		t.Skip("requires a running systemd-resolved test host")
	}
	servers, err := getNameserversFromResolved()
	if err != nil || len(servers) == 0 {
		t.Fatalf("resolved upstream discovery failed: %v, %v", servers, err)
	}
	t.Logf("resolved upstreams: %v", servers)
	all := Nameservers()
	for _, upstream := range servers {
		found := false
		for _, discovered := range all {
			if discovered.IP.Equal(upstream.IP) {
				found = true
			}
		}
		if !found {
			t.Errorf("resolved upstream missing from Nameservers: %v, all=%v", upstream, all)
		}
	}
}

func TestResolvedNameserversRejectsMalformedProperties(t *testing.T) {
	for _, props := range []map[string]dbus.Variant{
		{},
		{"DNS": dbus.MakeVariant("unexpected"), "Domains": dbus.MakeVariant([][]any{})},
		{"DNS": dbus.MakeVariant([][]any{}), "Domains": dbus.MakeVariant("unexpected")},
	} {
		if _, err := resolvedNameservers(props); err == nil {
			t.Fatal("malformed property accepted")
		}
	}
}

func TestResolvedDNSRoutingSnapshotPreservesRootAndUnavailableLinks(t *testing.T) {
	properties := map[string]dbus.Variant{
		"DNS": dbus.MakeVariant([][]any{
			{int32(2), int32(2), []byte{10, 20, 0, 53}},
			{int32(7), int32(10), []byte(net.ParseIP("fd00::53").To16())},
			{int32(9), int32(10), []byte(net.ParseIP("fe80::53").To16())},
		}),
		"Domains": dbus.MakeVariant([][]any{
			{int32(2), "corp.policy-fixture.com", false},
			{int32(7), "vpn.policy-fixture.com", true},
			{int32(7), ".", true},
			{int32(9), "unavailable.policy-fixture.com", true},
			{int32(42), "no-server.policy-fixture.com", true},
		}),
	}
	snapshot, err := resolvedDNSConfiguration(properties)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Nameservers) != 2 {
		t.Fatalf("unexpected global/scoped DNS metadata: %+v", snapshot.Nameservers)
	}
	if snapshot.Nameservers[0].ScopeOnly || !snapshot.Nameservers[1].ScopeOnly {
		t.Fatal("lost routing-only server restriction")
	}
	rules := map[string]DNSRoutingRule{}
	for _, r := range snapshot.Rules {
		rules[r.Namespace] = r
	}
	if len(rules) != 5 {
		t.Fatalf("routing-only/root/unavailable scope lost: %+v", snapshot.Rules)
	}
	if r := rules["."]; len(r.Servers) != 1 || !r.Servers[0].Equal(net.ParseIP("fd00::53")) {
		t.Fatal("root lost its upstream association")
	}
	for _, name := range []string{"unavailable.policy-fixture.com.", "no-server.policy-fixture.com."} {
		if r, ok := rules[name]; !ok || len(r.Servers) != 0 {
			t.Fatalf("unavailable scope not retained as a fence: %s %+v", name, r)
		}
	}
}

func TestResolvedDNSRoutingSnapshotMergesOnlyMatchingLinkPeers(t *testing.T) {
	properties := map[string]dbus.Variant{
		"DNS":     dbus.MakeVariant([][]any{{int32(2), int32(2), []byte{10, 20, 0, 53}}, {int32(7), int32(2), []byte{10, 20, 0, 54}}, {int32(9), int32(2), []byte{192, 0, 2, 53}}}),
		"Domains": dbus.MakeVariant([][]any{{int32(2), "corp.policy-fixture.com", true}, {int32(7), "corp.policy-fixture.com", true}, {int32(9), "other.policy-fixture.com", false}}),
	}
	snapshot, err := resolvedDNSConfiguration(properties)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range snapshot.Rules {
		if r.Namespace == "corp.policy-fixture.com." {
			if len(r.Servers) != 2 || r.Servers[0].String() != "10.20.0.53" || r.Servers[1].String() != "10.20.0.54" {
				t.Fatalf("private peers lost or unrelated link included: %+v", r)
			}
			return
		}
	}
	t.Fatal("private route missing")
}

func TestResolvedExplicitDefaultRouteAllowsGlobalFallback(t *testing.T) {
	properties := map[string]dbus.Variant{
		"DNS":     dbus.MakeVariant([][]any{{int32(7), int32(2), []byte{10, 20, 0, 53}}}),
		"Domains": dbus.MakeVariant([][]any{{int32(7), "vpn.policy-fixture.com", true}}),
	}
	configuration, err := resolvedDNSConfigurationWithDefaultRoutes(properties, map[int32]bool{7: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(configuration.Nameservers) != 1 || configuration.Nameservers[0].ScopeOnly {
		t.Fatal("explicit OS DefaultRoute=true was ignored")
	}
	if len(configuration.Rules) != 1 {
		t.Fatal("default-route setting removed private namespace fence")
	}
	configuration, err = resolvedDNSConfigurationWithDefaultRoutes(properties, map[int32]bool{7: false})
	if err != nil {
		t.Fatal(err)
	}
	if !configuration.Nameservers[0].ScopeOnly {
		t.Fatal("explicit OS DefaultRoute=false was ignored")
	}
}
