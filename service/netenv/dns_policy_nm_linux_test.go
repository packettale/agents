package netenv

import (
	"net"
	"testing"

	"github.com/godbus/dbus/v5"
)

func TestNetworkManagerDNSManagerPropertyDecoding(t *testing.T) {
	properties := map[string]dbus.Variant{
		"Mode": dbus.MakeVariant("default"),
		"Configuration": dbus.MakeVariant([]map[string]dbus.Variant{
			{"nameservers": dbus.MakeVariant([]string{"192.0.2.53"}), "priority": dbus.MakeVariant(int32(100)), "interface": dbus.MakeVariant("eth0"), "vpn": dbus.MakeVariant(false)},
			{"nameservers": dbus.MakeVariant([]string{"10.20.0.53"}), "domains": dbus.MakeVariant([]string{"~corp.policy-fixture.com"}), "priority": dbus.MakeVariant(int32(-50)), "interface": dbus.MakeVariant("tun0"), "vpn": dbus.MakeVariant(true)},
		}),
	}
	configuration, err := networkManagerDNSProperties(properties)
	if err != nil || len(configuration.Nameservers) != 1 || len(configuration.Rules) != 2 {
		t.Fatalf("lost DnsManager priority or routing domain metadata: %+v %v", configuration, err)
	}
	for _, rule := range configuration.Rules {
		if len(rule.Servers) != 1 || !rule.Servers[0].Equal(net.ParseIP("10.20.0.53")) {
			t.Fatalf("DNS manager decoder included an excluded interface: %+v", rule)
		}
	}
}

func TestNetworkManagerGlobalWildcardExcludesInterfaceServers(t *testing.T) {
	global := nmFixture(100, "192.0.2.53")
	global.Global = true
	configuration, err := networkManagerPriorityConfiguration("default", []networkManagerDNSSettings{
		nmFixture(50, "10.20.0.53", "~corp.policy-fixture.com"), global,
	})
	if err != nil || len(configuration.Nameservers) != 1 || len(configuration.Rules) != 1 || configuration.Rules[0].Namespace != "." || !configuration.Rules[0].Servers[0].Equal(net.ParseIP("192.0.2.53")) {
		t.Fatalf("global wildcard did not replace interface configuration: %+v %v", configuration, err)
	}
}

func TestNetworkManagerMissingOrUnsupportedMetadataIsRejected(t *testing.T) {
	for _, properties := range []map[string]dbus.Variant{
		{},
		{"Mode": dbus.MakeVariant("default"), "Configuration": dbus.MakeVariant("invalid")},
		{"Mode": dbus.MakeVariant("default"), "Configuration": dbus.MakeVariant([]map[string]dbus.Variant{{"nameservers": dbus.MakeVariant([]string{"192.0.2.53"})}})},
		{"Mode": dbus.MakeVariant("default"), "Configuration": dbus.MakeVariant([]map[string]dbus.Variant{{"nameservers": dbus.MakeVariant([]string{"dns+tls://192.0.2.53"}), "priority": dbus.MakeVariant(int32(100))}})},
	} {
		if _, err := networkManagerDNSProperties(properties); err == nil {
			t.Errorf("accepted incomplete/unsupported DNS metadata: %+v", properties)
		}
	}
}

func nmFixture(priority int32, server string, domains ...string) networkManagerDNSSettings {
	return networkManagerDNSSettings{Priority: priority, Servers: []net.IP{net.ParseIP(server)}, Domains: domains}
}

func TestNetworkManagerPrioritySelectsScopedPeers(t *testing.T) {
	configuration, err := networkManagerPriorityConfiguration("default", []networkManagerDNSSettings{
		nmFixture(100, "192.0.2.53", "corp.policy-fixture.com"),
		nmFixture(50, "10.20.0.53", "~corp.policy-fixture.com"),
		nmFixture(50, "10.20.0.54", "~corp.policy-fixture.com"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(configuration.Rules) != 1 || len(configuration.Rules[0].Servers) != 2 {
		t.Fatalf("lower-priority DNS server entered the private peer set: %+v", configuration.Rules)
	}
	if !configuration.Rules[0].Servers[0].Equal(net.ParseIP("10.20.0.53")) || !configuration.Rules[0].Servers[1].Equal(net.ParseIP("10.20.0.54")) {
		t.Fatal("equal-priority failover order changed")
	}
}

func TestNetworkManagerNegativePriorityRestrictsDefaultMode(t *testing.T) {
	configuration, err := networkManagerPriorityConfiguration("default", []networkManagerDNSSettings{
		nmFixture(100, "192.0.2.53", "corp.policy-fixture.com"),
		nmFixture(-50, "10.20.0.53", "~corp.policy-fixture.com"),
		nmFixture(-100, "10.30.0.53", "~vpn.policy-fixture.com"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(configuration.Nameservers) != 1 || !configuration.Nameservers[0].IP.Equal(net.ParseIP("10.30.0.53")) {
		t.Fatalf("negative priority did not exclude other configurations: %+v", configuration.Nameservers)
	}
	root := false
	for _, rule := range configuration.Rules {
		root = root || rule.Namespace == "."
		if len(rule.Servers) != 1 || !rule.Servers[0].Equal(net.ParseIP("10.30.0.53")) {
			t.Fatalf("negative-priority route included another server: %+v", rule)
		}
	}
	if !root {
		t.Fatal("negative priority lost its default route and permits unrelated configured DNS")
	}
}

func TestNetworkManagerDelegatedPolicyCannotBeFlattened(t *testing.T) {
	for _, mode := range []string{"systemd-resolved", "dnsconfd", "unexpected"} {
		if _, err := networkManagerPriorityConfiguration(mode, []networkManagerDNSSettings{nmFixture(100, "192.0.2.53")}); err == nil {
			t.Errorf("flattened delegated/unknown DNS mode %q", mode)
		}
	}
	if _, err := networkManagerPriorityConfiguration("dnsmasq", []networkManagerDNSSettings{nmFixture(-50, "10.20.0.53", "~corp.policy-fixture.com")}); err == nil {
		t.Fatal("unsupported negative parent-domain policy silently ignored")
	}
}

func TestNetworkManagerRootRoutingShorthandIsRetained(t *testing.T) {
	configuration, err := networkManagerDNSConfiguration([]net.IP{net.ParseIP("10.20.0.53")}, []string{"~"}, nil)
	if err != nil || len(configuration.Rules) != 1 || configuration.Rules[0].Namespace != "." {
		t.Fatalf("NetworkManager root shorthand lost its default-route fence: %+v %v", configuration, err)
	}
}

func TestNetworkManagerDNSMasqIncompleteEffectiveRoutesAreRejected(t *testing.T) {
	properties := map[string]dbus.Variant{
		"Mode": dbus.MakeVariant("dnsmasq"),
		"Configuration": dbus.MakeVariant([]map[string]dbus.Variant{
			{"priority": dbus.MakeVariant(int32(50)), "nameservers": dbus.MakeVariant([]string{"10.20.0.53"}), "interface": dbus.MakeVariant("tun0"), "vpn": dbus.MakeVariant(true)},
			{"priority": dbus.MakeVariant(int32(100)), "nameservers": dbus.MakeVariant([]string{"192.0.2.53"}), "interface": dbus.MakeVariant("eth0"), "vpn": dbus.MakeVariant(false)},
		}),
	}
	if configuration, err := networkManagerDNSProperties(properties); err == nil {
		t.Fatalf("implicit VPN default route could be lost without a visible fence: %+v", configuration)
	}
}
