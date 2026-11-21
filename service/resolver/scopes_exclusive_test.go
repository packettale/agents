package resolver

import (
	"context"
	"reflect"
	"testing"

	"github.com/miekg/dns"
	"github.com/packettale/agents/service/netenv"
)

func TestExclusiveSearchConfiguration(t *testing.T) {
	for _, tc := range []struct {
		url   string
		valid bool
	}{
		{"dns://10.20.0.53?search=office.scope-fixture.com&search-exclusive", true},
		{"dns://10.20.0.53?search=office.scope-fixture.com&search-only&search-exclusive", true},
		{"dns://10.20.0.53?search-exclusive", false},
		{"dns://10.20.0.53?search=office.scope-fixture.com&search-exclusive=true", false},
	} {
		t.Run(tc.url, func(t *testing.T) {
			_, skip, err := createResolver(tc.url, ServerSourceConfigured)
			if (err == nil && !skip) != tc.valid {
				t.Fatalf("accepted=%v want %v; error=%v", err == nil && !skip, tc.valid, err)
			}
		})
	}
}

func TestExclusiveSearchSelection(t *testing.T) {
	// No transport is called. These are reserved documentation IPs and test names.
	oldGlobal, oldLocal, oldSystem, oldScopes := globalResolvers, localResolvers, systemResolvers, localScopes
	oldPolicy := systemPolicyScopes
	systemPolicyScopes = nil
	oldInsecure, oldAssigned := noInsecureProtocols, noAssignedNameservers
	t.Cleanup(func() {
		globalResolvers, localResolvers, systemResolvers, localScopes = oldGlobal, oldLocal, oldSystem, oldScopes
		systemPolicyScopes = oldPolicy
		noInsecureProtocols, noAssignedNameservers = oldInsecure, oldAssigned
	})
	noInsecureProtocols = func() bool { return false }
	noAssignedNameservers = func() bool { return false }
	for _, tc := range []struct {
		name, query        string
		urls               []string
		want               []string
		insecure, assigned bool
		wantTryAll         bool
	}{
		{name: "private suffix excludes global fallback", query: "app.office.scope-fixture.com", urls: []string{"dns://192.0.2.1", "dns://10.20.0.53?search=office.scope-fixture.com&search-exclusive"}, want: []string{"10.20.0.53"}},
		{name: "scope apex", query: "office.scope-fixture.com", urls: []string{"dns://192.0.2.1", "dns://10.20.0.53?search=office.scope-fixture.com&search-exclusive"}, want: []string{"10.20.0.53"}},
		{name: "suffix label boundary", query: "app.otheroffice.scope-fixture.com", urls: []string{"dns://192.0.2.1", "dns://10.20.0.53?search=office.scope-fixture.com&search-only&search-exclusive"}, want: []string{"192.0.2.1"}},
		{name: "special-use suffix also fenced", query: "app.office.test", urls: []string{"dns://10.20.0.54", "dns://10.20.0.53?search=office.test&search-exclusive"}, want: []string{"10.20.0.53"}},
		{name: "same strict scope preserves failover order", query: "app.office.scope-fixture.com", urls: []string{"dns://192.0.2.1", "dns://10.20.0.53?search=office.scope-fixture.com&search-exclusive", "dns://10.20.0.54?search=office.scope-fixture.com&search-exclusive"}, want: []string{"10.20.0.53", "10.20.0.54"}},
		{name: "same scope soft server cannot enter fence", query: "app.office.scope-fixture.com", urls: []string{"dns://192.0.2.1?search=office.scope-fixture.com", "dns://10.20.0.53?search=office.scope-fixture.com&search-exclusive"}, want: []string{"10.20.0.53"}},
		{name: "most specific strict scope wins", query: "app.child.office.scope-fixture.com", urls: []string{"dns://10.20.0.53?search=office.scope-fixture.com&search-exclusive", "dns://10.20.0.54?search=child.office.scope-fixture.com&search-exclusive"}, want: []string{"10.20.0.54"}},
		{name: "soft child cannot relax strict parent", query: "app.child.office.scope-fixture.com", urls: []string{"dns://192.0.2.1?search=child.office.scope-fixture.com", "dns://10.20.0.53?search=office.scope-fixture.com&search-exclusive"}, want: []string{"10.20.0.53"}},
		{name: "insecure restriction does not relax strict scope", query: "app.office.scope-fixture.com", urls: []string{"dot://192.0.2.1?verify=dns.scope-fixture.com", "dns://10.20.0.53?search=office.scope-fixture.com&search-exclusive"}, want: []string{}, insecure: true},
		{name: "unrelated queries retain regular order", query: "www.unrelated.scope-fixture.com", urls: []string{"dns://192.0.2.1", "dns://10.20.0.53?search=office.scope-fixture.com&search-exclusive&search-only"}, want: []string{"192.0.2.1"}},
		{name: "existing soft search retains fallback", query: "app.office.scope-fixture.com", urls: []string{"dns://192.0.2.1", "dns://10.20.0.53?search=office.scope-fixture.com&search-only"}, want: []string{"10.20.0.53", "192.0.2.1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			list := make([]*Resolver, 0, len(tc.urls))
			for _, u := range tc.urls {
				r, skip, err := createResolver(u, ServerSourceConfigured)
				if err != nil || skip {
					t.Fatalf("resolver setup: %s: %v", u, err)
				}
				list = append(list, r)
			}
			globalResolvers = list
			setScopedResolvers(list)
			noInsecureProtocols = func() bool { return tc.insecure }
			noAssignedNameservers = func() bool { return tc.assigned }
			q := &Query{FQDN: tc.query + ".", QType: dns.Type(dns.TypeA)}
			if !q.check() {
				t.Fatal("invalid fixture name")
			}
			selected, _, tryAll := GetResolversInScope(context.Background(), q)
			got := make([]string, 0, len(selected))
			for _, r := range selected {
				got = append(got, r.Info.IP.String())
			}
			if !reflect.DeepEqual(got, tc.want) || tryAll != tc.wantTryAll {
				t.Fatalf("selected=%v tryAll=%v; want=%v tryAll=%v", got, tryAll, tc.want, tc.wantTryAll)
			}
		})
	}
}

func TestExclusiveSearchChangesCacheContext(t *testing.T) {
	soft, _, err := createResolver("dns://10.20.0.53?search=office.scope-fixture.com", ServerSourceConfigured)
	if err != nil {
		t.Fatal(err)
	}
	strict, _, err := createResolver("dns://10.20.0.53?search=office.scope-fixture.com&search-exclusive", ServerSourceConfigured)
	if err != nil {
		t.Fatal(err)
	}
	// Compare the routing bit independently of the already-hashed URL.
	strict.ConfigURL = soft.ConfigURL
	prepareResolverCacheContext([]*Resolver{soft}, nil)
	prepareResolverCacheContext([]*Resolver{strict}, nil)
	if soft.Info.CacheContext == strict.Info.CacheContext {
		t.Fatal("strict scope transition reused old cache context")
	}
}

type scopeResponseConn struct {
	response *RRCache
	err      error
	calls    int
	failing  bool
	onQuery  func()
}

func (c *scopeResponseConn) Query(context.Context, *Query) (*RRCache, error) {
	c.calls++
	if c.onQuery != nil {
		c.onQuery()
	}
	return c.response, c.err
}
func (c *scopeResponseConn) ReportFailure()                 {}
func (c *scopeResponseConn) IsFailing() bool                { return c.failing }
func (c *scopeResponseConn) ResetFailure()                  {}
func (c *scopeResponseConn) ForceReconnect(context.Context) {}

func TestExclusiveSearchQueryFailuresStayPrivate(t *testing.T) {
	oldGlobal, oldLocal, oldSystem, oldScopes := globalResolvers, localResolvers, systemResolvers, localScopes
	oldPolicy := systemPolicyScopes
	systemPolicyScopes = nil
	oldInsecure, oldAssigned := noInsecureProtocols, noAssignedNameservers
	t.Cleanup(func() {
		globalResolvers, localResolvers, systemResolvers, localScopes = oldGlobal, oldLocal, oldSystem, oldScopes
		systemPolicyScopes = oldPolicy
		noInsecureProtocols, noAssignedNameservers = oldInsecure, oldAssigned
	})
	noInsecureProtocols = func() bool { return false }
	noAssignedNameservers = func() bool { return false }
	// The existing connectivity-test exception permits resolution even when the
	// test environment is offline. Both transports below are in-memory stubs.
	for _, tc := range []struct {
		name                 string
		rcode                int
		err                  error
		failing, unavailable bool
	}{
		{name: "authoritative NXDOMAIN", rcode: dns.RcodeNameError},
		{name: "server failure", rcode: dns.RcodeServerFailure},
		{name: "timeout", err: ErrTimeout},
		{name: "cancellation", err: context.Canceled},
		{name: "already failing private resolver", failing: true},
		{name: "unreachable private link", unavailable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			private, skip, err := createResolver("dns://10.20.0.53?search=safing.io&search-exclusive", ServerSourceOperatingSystem)
			if err != nil || skip {
				t.Fatal("private setup", err)
			}
			public, skip, err := createResolver("dns://192.0.2.1", ServerSourceConfigured)
			if err != nil || skip {
				t.Fatal("public setup", err)
			}
			q := &Query{FQDN: netenv.DNSTestDomain, QType: dns.Type(dns.TypeA), NoCaching: true}
			if !q.check() {
				t.Fatal("invalid query")
			}
			privateConn := &scopeResponseConn{response: &RRCache{Domain: q.FQDN, Question: q.QType, RCode: tc.rcode, Resolver: private.Info}, err: tc.err, failing: tc.failing}
			publicConn := &scopeResponseConn{response: &RRCache{Domain: q.FQDN, Question: q.QType, RCode: dns.RcodeSuccess, Resolver: public.Info}}
			private.Conn = privateConn
			private.LinkLocalUnavailable = tc.unavailable
			public.Conn = publicConn
			globalResolvers = []*Resolver{public, private}
			setScopedResolvers(globalResolvers)
			response, err := resolveAndCache(context.Background(), q, nil)
			if publicConn.calls != 0 {
				t.Fatalf("private query reached unrelated public resolver %d times", publicConn.calls)
			}
			wantCalls := 1
			if tc.failing || tc.unavailable {
				wantCalls = 0
			}
			if privateConn.calls != wantCalls {
				t.Fatalf("private calls=%d want %d", privateConn.calls, wantCalls)
			}
			if tc.err == nil && !tc.failing && !tc.unavailable {
				if err != nil || response == nil || response.RCode != tc.rcode {
					t.Fatalf("private result lost: response=%v error=%v", response, err)
				}
			} else if err == nil {
				t.Fatal("private failure unexpectedly succeeded")
			}
		})
	}
}
