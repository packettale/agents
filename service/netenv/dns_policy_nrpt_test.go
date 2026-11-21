package netenv

import (
	"net"
	"testing"
)

func TestWindowsNRPTPolicyConversion(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		record                 windowsDNSPolicy
		domain                 string
		exact, exempt, blocked bool
	}{
		{name: "generic suffix", record: windowsDNSPolicy{Namespace: ".Corp.Example", NameServers: []string{"10.20.0.53", "fd00::53"}}, domain: "corp.example."},
		{name: "exact host", record: windowsDNSPolicy{Namespace: "host.corp.example", NameServers: []string{"10.20.0.53"}}, domain: "host.corp.example.", exact: true},
		{name: "default route", record: windowsDNSPolicy{Namespace: ".", NameServers: []string{"10.20.0.53"}}, domain: "."},
		{name: "exact exemption", record: windowsDNSPolicy{Namespace: "public.corp.example"}, domain: "public.corp.example.", exact: true, exempt: true},
		{name: "suffix exemption", record: windowsDNSPolicy{Namespace: ".public.corp.example"}, domain: "public.corp.example.", exempt: true},
		{name: "DNSSEC required", record: windowsDNSPolicy{Namespace: ".secure.corp.example", NameServers: []string{"10.20.0.53"}, DNSSECRequired: true}, domain: "secure.corp.example.", blocked: true},
		{name: "IPsec required", record: windowsDNSPolicy{Namespace: ".secure.corp.example", NameServers: []string{"10.20.0.53"}, IPsecRequired: true}, domain: "secure.corp.example.", blocked: true},
		{name: "DirectAccess cannot be silently downgraded", record: windowsDNSPolicy{Namespace: ".corp.example", NameServers: []string{"10.20.0.53"}, DirectAccess: true}, domain: "corp.example.", blocked: true},
		{name: "hostname upstream cannot bootstrap outside policy", record: windowsDNSPolicy{Namespace: ".corp.example", NameServers: []string{"dns.corp.example"}}, domain: "corp.example.", blocked: true},
		{name: "link-local upstream needs zone support", record: windowsDNSPolicy{Namespace: ".corp.example", NameServers: []string{"fe80::53"}}, domain: "corp.example.", blocked: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := windowsDNSPolicyRules([]windowsDNSPolicy{tc.record})
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 {
				t.Fatalf("lost NRPT namespace: %+v", got)
			}
			r := got[0]
			if r.Namespace != tc.domain || r.Exact != tc.exact || r.Exempt != tc.exempt || r.Blocked != tc.blocked || r.Priority != DNSRoutePolicy {
				t.Fatalf("unexpected mode: %+v", r)
			}
			if !tc.blocked && !tc.exempt && len(r.Servers) != len(tc.record.NameServers) {
				t.Fatalf("lost server failover: %+v", r)
			}
		})
	}
}

func TestWindowsNRPTConversionRejectsMalformedSnapshots(t *testing.T) {
	for _, records := range [][]windowsDNSPolicy{
		{{Namespace: ""}}, {{Namespace: "..corp.example"}}, {{Namespace: "*.corp.example"}},
		make([]windowsDNSPolicy, 1001),
	} {
		if _, err := windowsDNSPolicyRules(records); err == nil {
			t.Fatal("malformed NRPT snapshot accepted")
		}
	}
	// Native empty policy must remove previous rules, not retain a stale fence.
	rules, err := windowsDNSPolicyRules(nil)
	if err != nil || len(rules) != 0 {
		t.Fatal(rules, err)
	}
}

func TestWindowsNRPTConflictingDuplicateNamespaceIsBlocked(t *testing.T) {
	rules, err := windowsDNSPolicyRules([]windowsDNSPolicy{
		{Namespace: ".corp.example", NameServers: []string{"10.20.0.53"}},
		{Namespace: ".corp.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || !rules[0].Blocked || rules[0].Exempt {
		t.Fatalf("conflicting policy silently relaxed: %+v", rules)
	}
	if !rules[0].Servers[0].Equal(net.ParseIP("10.20.0.53")) {
		t.Fatal("lost diagnostic target")
	}
}
