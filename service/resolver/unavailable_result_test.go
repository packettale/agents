package resolver

import (
	"context"
	"errors"
	"testing"

	"github.com/packettale/agents/service/netenv"
	"github.com/miekg/dns"
)

func TestUnavailableResolversAreNotNegativeDNSAnswers(t *testing.T) {
	preserveDNSResolverState(t)
	oldInsecure, oldAssigned := noInsecureProtocols, noAssignedNameservers
	t.Cleanup(func() { noInsecureProtocols, noAssignedNameservers = oldInsecure, oldAssigned })
	noInsecureProtocols = func() bool { return false }
	noAssignedNameservers = func() bool { return false }
	for _, tc := range []struct {
		name                 string
		failing, unavailable bool
	}{
		{name: "all resolvers temporarily failing", failing: true},
		{name: "all links unavailable", unavailable: true},
		{name: "transport returns no result"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, skip, err := createResolver("dns://192.0.2.53", ServerSourceConfigured)
			if err != nil || skip {
				t.Fatalf("fixture resolver: %v", err)
			}
			conn := &scopeResponseConn{failing: tc.failing}
			r.Conn, r.LinkLocalUnavailable = conn, tc.unavailable
			globalResolvers, systemPolicyScopes = []*Resolver{r}, nil
			setScopedResolvers(globalResolvers)
			// The test-domain exception permits this in-memory query when the
			// fixture network is offline. No external transport is used.
			q := &Query{FQDN: netenv.DNSTestDomain, QType: dns.Type(dns.TypeAAAA), NoCaching: true}
			if !q.check() {
				t.Fatal("invalid query")
			}
			response, err := resolveAndCache(context.Background(), q, nil)
			if response != nil || !errors.Is(err, ErrFailure) || errors.Is(err, ErrNotFound) {
				t.Fatalf("unavailable DNS path must fail without claiming NXDOMAIN: response=%v error=%v", response, err)
			}
			if (tc.failing || tc.unavailable) && conn.calls != 0 {
				t.Fatal("unavailable resolver was queried")
			}
		})
	}
}

func TestDNSResponsesKeepNoDataDistinctFromNXDOMAIN(t *testing.T) {
	preserveDNSResolverState(t)
	oldInsecure, oldAssigned := noInsecureProtocols, noAssignedNameservers
	t.Cleanup(func() { noInsecureProtocols, noAssignedNameservers = oldInsecure, oldAssigned })
	noInsecureProtocols = func() bool { return false }
	noAssignedNameservers = func() bool { return false }
	for _, code := range []int{dns.RcodeSuccess, dns.RcodeNameError} {
		t.Run(dns.RcodeToString[code], func(t *testing.T) {
			r, skip, err := createResolver("dns://192.0.2.53", ServerSourceConfigured)
			if err != nil || skip {
				t.Fatalf("fixture resolver: %v", err)
			}
			q := &Query{FQDN: netenv.DNSTestDomain, QType: dns.Type(dns.TypeAAAA), NoCaching: true}
			if !q.check() {
				t.Fatal("invalid query")
			}
			r.Conn = &scopeResponseConn{response: &RRCache{Domain: q.FQDN, Question: q.QType, RCode: code, Resolver: r.Info}}
			globalResolvers, systemPolicyScopes = []*Resolver{r}, nil
			setScopedResolvers(globalResolvers)
			response, err := resolveAndCache(context.Background(), q, nil)
			if err != nil || response == nil || response.RCode != code {
				t.Fatalf("DNS answer semantics changed: response=%v error=%v", response, err)
			}
		})
	}
}
