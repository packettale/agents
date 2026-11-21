package netenv

import (
	"net"
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeDNSRoutingRules(t *testing.T) {
	for _, tc := range []struct {
		name, domain string
		exact, valid bool
		want         string
	}{
		{name: "suffix canonical form", domain: "CORP.Example", valid: true, want: "corp.example."},
		{name: "exact name stays exact", domain: "Host.Corp.Example.", exact: true, valid: true, want: "host.corp.example."},
		{name: "root route", domain: ".", valid: true, want: "."},
		{name: "empty namespace", domain: ""},
		{name: "invalid label boundary", domain: "corp..example"},
		{name: "wildcard is not a suffix", domain: "*.corp.example"},
		{name: "suffix syntax belongs to provider", domain: ".corp.example"},
		{name: "root cannot be exact", domain: ".", exact: true},
		{name: "bounded namespace", domain: strings.Repeat("a.", 150)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeDNSRoutingRules([]DNSRoutingRule{{Namespace: tc.domain, Exact: tc.exact, Priority: DNSRoutePolicy, Servers: []net.IP{net.ParseIP("10.20.0.53")}}})
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v want %v error=%v", err == nil, tc.valid, err)
			}
			if err == nil && (len(got) != 1 || got[0].Namespace != tc.want || got[0].Exact != tc.exact) {
				t.Fatalf("unexpected canonical rule: %+v", got)
			}
		})
	}
}

func TestDNSRulesPreserveUnavailableAndExemptionStates(t *testing.T) {
	rules := []DNSRoutingRule{
		{Namespace: "corp.example", Priority: DNSRouteLink},
		{Namespace: "public.corp.example", Exact: true, Exempt: true, Priority: DNSRoutePolicy},
		{Namespace: "secure.corp.example", Blocked: true, Priority: DNSRoutePolicy, Servers: []net.IP{net.ParseIP("10.20.0.53")}},
	}
	got, err := NormalizeDNSRoutingRules(rules)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("lost routes with empty/blocked/exempt upstreams: %+v", got)
	}
	found := map[string]DNSRoutingRule{}
	for _, r := range got {
		found[r.Namespace] = r
	}
	if !found["public.corp.example."].Exempt || !found["secure.corp.example."].Blocked {
		t.Fatal("lost policy mode")
	}
	if len(found["corp.example."].Servers) != 0 {
		t.Fatal("invented upstream for unavailable private namespace")
	}
}

func TestDNSRulesMergePeersWithoutAliasingProviderData(t *testing.T) {
	first := net.ParseIP("10.20.0.53")
	second := net.ParseIP("fd00::53")
	input := []DNSRoutingRule{
		{Namespace: "CORP.EXAMPLE", Priority: DNSRouteLink, Servers: []net.IP{first}},
		{Namespace: "corp.example.", Priority: DNSRouteLink, Servers: []net.IP{first, second}},
		{Namespace: "corp.example.", Priority: DNSRoutePolicy, Exempt: true},
	}
	got, err := NormalizeDNSRoutingRules(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Priority != DNSRoutePolicy || !got[0].Exempt || len(got[1].Servers) != 2 {
		t.Fatalf("wrong peer merge/precedence: %+v", got)
	}
	got[1].Servers[0][0] = 99
	if !first.Equal(net.ParseIP("10.20.0.53")) || input[0].Namespace != "CORP.EXAMPLE" {
		t.Fatal("mutated OS provider data")
	}
	again, err := NormalizeDNSRoutingRules(input)
	if err != nil {
		t.Fatal(err)
	}
	reverse := []DNSRoutingRule{input[2], input[0], input[1]}
	other, err := NormalizeDNSRoutingRules(reverse)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(again, other) {
		t.Fatal("irrelevant namespace ordering changed canonical snapshot")
	}
}

func TestDNSRulesRejectUnsafeUpstreamsAndConflictingModes(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "0.0.0.0", "224.0.0.1", "::1", "fe80::53", "::"} {
		got, err := NormalizeDNSRoutingRules([]DNSRoutingRule{{Namespace: "corp.example", Priority: DNSRoutePolicy, Servers: []net.IP{net.ParseIP(ip)}}})
		if err != nil || len(got) != 1 || len(got[0].Servers) != 0 || !got[0].Blocked {
			t.Fatalf("unsafe upstream %s did not fence namespace: %+v %v", ip, got, err)
		}
	}
	_, err := NormalizeDNSRoutingRules([]DNSRoutingRule{{Namespace: "corp.example", Priority: DNSRoutePolicy, Exempt: true, Servers: []net.IP{net.ParseIP("10.20.0.53")}}})
	if err == nil {
		t.Fatal("exemption cannot simultaneously nominate DNS servers")
	}
	_, err = NormalizeDNSRoutingRules(make([]DNSRoutingRule, 1001))
	if err == nil {
		t.Fatal("unbounded rule snapshot accepted")
	}
}
