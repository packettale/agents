package netenv

import (
	"bytes"
	"net"
	"testing"
)

func TestDNSFingerprintDetectsChangesWithoutOrderChurn(t *testing.T) {
	a := Nameserver{IP: net.ParseIP("10.20.0.53"), Search: []string{"office.example", "branch.example"}}
	b := Nameserver{IP: net.ParseIP("fd00::53"), Search: []string{"vpn.example"}}
	first := dnsConfigurationFingerprint([]Nameserver{a, b}, []string{"global.example", "secondary.example"})
	a.Search = []string{"branch.example", "office.example"}
	if !bytes.Equal(first, dnsConfigurationFingerprint([]Nameserver{b, a}, []string{"secondary.example", "global.example"})) {
		t.Fatal("equivalent DNS order triggered a network change")
	}
	a.Search = []string{"remote.example"}
	if bytes.Equal(first, dnsConfigurationFingerprint([]Nameserver{a, b}, []string{"global.example", "secondary.example"})) {
		t.Fatal("DNS suffix change was missed")
	}
	a.Search = []string{"office.example", "branch.example"}
	a.IP = net.ParseIP("10.30.0.53")
	if bytes.Equal(first, dnsConfigurationFingerprint([]Nameserver{a, b}, []string{"global.example", "secondary.example"})) {
		t.Fatal("DNS server change was missed")
	}
	a.IP = net.ParseIP("10.20.0.53")
	if bytes.Equal(first, dnsConfigurationFingerprint([]Nameserver{a, b}, []string{"new.example"})) {
		t.Fatal("global DNS search-list change was missed")
	}
}

func TestDNSFingerprintDoesNotMutateProviderData(t *testing.T) {
	scopes := []string{"z.example", "a.example"}
	extra := []string{"z", "a"}
	dnsConfigurationFingerprint([]Nameserver{{IP: net.ParseIP("10.0.0.53"), Search: scopes}}, extra)
	if scopes[0] != "z.example" || extra[0] != "z" {
		t.Fatal("fingerprint mutated shared provider data")
	}
}

func TestDNSFingerprintDetectsRoutingOnlyUpstreamChange(t *testing.T) {
	server := Nameserver{IP: net.ParseIP("10.20.0.53"), Search: []string{"corp.policy-fixture.com"}}
	before := dnsConfigurationFingerprint([]Nameserver{server}, nil)
	server.ScopeOnly = true
	if bytes.Equal(before, dnsConfigurationFingerprint([]Nameserver{server}, nil)) {
		t.Fatal("routing-only DNS changed without a monitor invalidation")
	}
}
