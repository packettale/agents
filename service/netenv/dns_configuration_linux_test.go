package netenv

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

func TestNativeLinuxDNSConfigurationMetadata(t *testing.T) {
	if os.Getenv("PACKETTALE_TEST_SYSTEM_DNS") != "1" {
		t.Skip("requires a controlled live Linux DNS configuration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	configuration, err := DNSConfiguration(ctx)
	if err != nil || len(configuration.Nameservers) == 0 {
		t.Fatalf("native effective DNS metadata unavailable: %v", err)
	}
	t.Logf("native DNS metadata: %d upstreams, %d routing rules", len(configuration.Nameservers), len(configuration.Rules))
}

func TestLinuxDNSProviderFallbackRequiresAbsence(t *testing.T) {
	for _, err := range []error{
		os.ErrNotExist,
		dbus.Error{Name: "org.freedesktop.DBus.Error.ServiceUnknown"},
		&dbus.Error{Name: "org.freedesktop.DBus.Error.NameHasNoOwner"},
	} {
		if !errors.Is(dnsProviderInitialError(err), errDNSProviderUnavailable) {
			t.Errorf("absent service was not recognized: %v", err)
		}
	}
	for _, err := range []error{
		os.ErrPermission, context.DeadlineExceeded,
		dbus.Error{Name: "org.freedesktop.DBus.Error.AccessDenied"},
		&dbus.Error{Name: "org.freedesktop.DBus.Error.UnknownProperty"},
	} {
		if errors.Is(dnsProviderInitialError(err), errDNSProviderUnavailable) {
			t.Errorf("unreadable active provider treated as absent: %v", err)
		}
	}
	absent := func(context.Context) (SystemDNSConfiguration, error) {
		return SystemDNSConfiguration{}, errDNSProviderUnavailable
	}
	file := func() ([]Nameserver, error) { return []Nameserver{{IP: net.ParseIP("192.0.2.53")}}, nil }
	configuration, err := dnsConfigurationFromProviders(context.Background(), absent, absent, file)
	if err != nil || len(configuration.Nameservers) != 1 {
		t.Fatalf("ordinary resolv.conf installation lost its supported fallback: %+v %v", configuration, err)
	}
	stub := func() ([]Nameserver, error) { return []Nameserver{{IP: net.ParseIP("127.0.0.53")}}, nil }
	if _, err := dnsConfigurationFromProviders(context.Background(), absent, absent, stub); err == nil {
		t.Fatal("resolved stub was accepted without its route metadata")
	}
}

func TestLinuxDNSProviderReadFailureDoesNotFlattenPrivatePolicy(t *testing.T) {
	readErr := errors.New("effective DNS security metadata unavailable")
	for _, failing := range []string{"resolved", "network-manager"} {
		t.Run(failing, func(t *testing.T) {
			fallbackCalled := false
			read := func(context.Context) (SystemDNSConfiguration, error) { return SystemDNSConfiguration{}, readErr }
			file := func() ([]Nameserver, error) {
				fallbackCalled = true
				return []Nameserver{{IP: net.ParseIP("192.0.2.53")}}, nil
			}
			other := func(context.Context) (SystemDNSConfiguration, error) {
				fallbackCalled = true
				return SystemDNSConfiguration{Nameservers: []Nameserver{{IP: net.ParseIP("192.0.2.53")}}}, nil
			}
			var err error
			if failing == "resolved" {
				_, err = dnsConfigurationFromProviders(context.Background(), read, other, file)
			} else {
				absent := func(context.Context) (SystemDNSConfiguration, error) {
					return SystemDNSConfiguration{}, errDNSProviderUnavailable
				}
				_, err = dnsConfigurationFromProviders(context.Background(), absent, read, file)
			}
			if !errors.Is(err, readErr) || fallbackCalled {
				t.Fatalf("live provider failure relaxed private policy: error=%v fallback=%v", err, fallbackCalled)
			}
		})
	}
}

func TestNetworkManagerRoutingMetadata(t *testing.T) {
	configuration, err := networkManagerDNSConfiguration([]net.IP{net.ParseIP("10.20.0.53")}, []string{"corp.policy-fixture.com"}, []string{"~vpn.policy-fixture.com", "~."})
	if err != nil {
		t.Fatal(err)
	}
	if len(configuration.Nameservers) != 1 || !configuration.Nameservers[0].ScopeOnly {
		t.Fatal("routing-only upstream entered the global DNS list")
	}
	if len(configuration.Rules) != 3 {
		t.Fatalf("lost explicit route metadata: %+v", configuration.Rules)
	}
	for _, r := range configuration.Rules {
		if r.Exact || r.Exempt || r.Blocked || len(r.Servers) != 1 || r.Priority != DNSRouteLink {
			t.Fatalf("wrong link route: %+v", r)
		}
	}
	for _, s := range configuration.Nameservers[0].Search {
		if s == "." || len(s) > 0 && s[0] == '~' {
			t.Fatal("routing-only syntax leaked into search scope")
		}
	}
}

func TestNetworkManagerMissingUpstreamKeepsPrivateFence(t *testing.T) {
	configuration, err := networkManagerDNSConfiguration([]net.IP{net.ParseIP("fe80::53")}, nil, []string{"~vpn.policy-fixture.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(configuration.Nameservers) != 0 || len(configuration.Rules) != 1 || len(configuration.Rules[0].Servers) != 0 {
		t.Fatalf("unsupported upstream relaxed private routing: %+v", configuration)
	}
}

func TestSystemDNSConfigurationObservesCanceledCaller(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DNSConfiguration(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("configuration ignored canceled caller: %v", err)
	}
}

func TestMergeNameserversRetainsRoutingOnlyUnlessGlobalPeerExists(t *testing.T) {
	scoped := Nameserver{IP: net.ParseIP("10.20.0.53"), Search: []string{"vpn.policy-fixture.com"}, ScopeOnly: true}
	other := Nameserver{IP: net.ParseIP("10.20.0.53"), Search: []string{"other.policy-fixture.com"}, ScopeOnly: true}
	merged := addNameservers([]Nameserver{scoped}, []Nameserver{other})
	if len(merged) != 1 || !merged[0].ScopeOnly {
		t.Fatal("private peer merge made an upstream global")
	}
	global := Nameserver{IP: net.ParseIP("10.20.0.53")}
	merged = addNameservers(merged, []Nameserver{global})
	if merged[0].ScopeOnly {
		t.Fatal("explicit global binding was lost")
	}
}
