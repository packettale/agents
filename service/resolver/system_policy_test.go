package resolver

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/packettale/agents/service/netenv"
)

func TestBuildSystemDNSPolicySharesOnlyEquivalentUpstreams(t *testing.T) {
	global, _, err := createResolver("dns://10.20.0.53", ServerSourceOperatingSystem)
	if err != nil {
		t.Fatal(err)
	}
	configured, _, err := createResolver("dns://10.20.0.53", ServerSourceConfigured)
	if err != nil {
		t.Fatal(err)
	}
	rules := []netenv.DNSRoutingRule{
		{Namespace: "corp.policy-fixture.com", Priority: netenv.DNSRoutePolicy, Servers: []net.IP{net.ParseIP("10.20.0.53")}},
		{Namespace: "child.corp.policy-fixture.com", Priority: netenv.DNSRoutePolicy, Servers: []net.IP{net.ParseIP("10.20.0.53"), net.ParseIP("10.20.0.54")}},
		{Namespace: "empty.corp.policy-fixture.com", Priority: netenv.DNSRoutePolicy},
	}
	scopes, extra, err := buildSystemDNSPolicy([]*Resolver{configured, global}, rules)
	if err != nil {
		t.Fatal(err)
	}
	if len(scopes) != 3 || len(extra) != 1 {
		t.Fatalf("wrong scope/upstream counts %d/%d", len(scopes), len(extra))
	}
	if extra[0].Info.IP.String() != "10.20.0.54" || extra[0].Info.Source != ServerSourceOperatingSystem {
		t.Fatal("wrong scoped-only upstream")
	}
	for _, scope := range scopes {
		for _, r := range scope.Resolvers {
			if r.Info.IP.String() == "10.20.0.53" && r != global {
				t.Fatal("same OS upstream not shared or confused with configured source")
			}
		}
	}
	if len(global.Search) != 0 || global.SearchOnly || global.SearchExclusive {
		t.Fatal("policy builder mutated global resolver behavior")
	}
}

func TestSystemDNSPolicySelection(t *testing.T) {
	oldGlobal, oldLocal, oldSystem, oldScopes, oldPolicy := globalResolvers, localResolvers, systemResolvers, localScopes, systemPolicyScopes
	oldInsecure, oldAssigned := noInsecureProtocols, noAssignedNameservers
	t.Cleanup(func() {
		globalResolvers, localResolvers, systemResolvers, localScopes, systemPolicyScopes = oldGlobal, oldLocal, oldSystem, oldScopes, oldPolicy
		noInsecureProtocols, noAssignedNameservers = oldInsecure, oldAssigned
	})
	for _, tc := range []struct {
		name, query        string
		rules              []netenv.DNSRoutingRule
		want               string
		insecure, assigned bool
		strict             string
	}{
		{name: "private suffix", query: "app.corp.policy-fixture.com", rules: []netenv.DNSRoutingRule{{Namespace: "corp.policy-fixture.com", Priority: netenv.DNSRoutePolicy, Servers: []net.IP{net.ParseIP("10.20.0.53")}}}, want: "10.20.0.53"},
		{name: "suffix apex", query: "corp.policy-fixture.com", rules: []netenv.DNSRoutingRule{{Namespace: "corp.policy-fixture.com", Priority: netenv.DNSRoutePolicy, Servers: []net.IP{net.ParseIP("10.20.0.53")}}}, want: "10.20.0.53"},
		{name: "suffix boundary", query: "othercorp.policy-fixture.com", rules: []netenv.DNSRoutingRule{{Namespace: "corp.policy-fixture.com", Priority: netenv.DNSRoutePolicy, Servers: []net.IP{net.ParseIP("10.20.0.53")}}}, want: "192.0.2.1"},
		{name: "exact exception", query: "public.corp.policy-fixture.com", rules: []netenv.DNSRoutingRule{{Namespace: "corp.policy-fixture.com", Priority: netenv.DNSRoutePolicy, Servers: []net.IP{net.ParseIP("10.20.0.53")}}, {Namespace: "public.corp.policy-fixture.com", Exact: true, Priority: netenv.DNSRoutePolicy, Exempt: true}}, want: "192.0.2.1"},
		{name: "exact does not cover child", query: "child.public.corp.policy-fixture.com", rules: []netenv.DNSRoutingRule{{Namespace: "corp.policy-fixture.com", Priority: netenv.DNSRoutePolicy, Servers: []net.IP{net.ParseIP("10.20.0.53")}}, {Namespace: "public.corp.policy-fixture.com", Exact: true, Priority: netenv.DNSRoutePolicy, Exempt: true}}, want: "10.20.0.53"},
		{name: "default route", query: "www.public.policy-fixture.com", rules: []netenv.DNSRoutingRule{{Namespace: ".", Priority: netenv.DNSRoutePolicy, Servers: []net.IP{net.ParseIP("10.20.0.53")}}}, want: "10.20.0.53"},
		{name: "native policy overrides interface scope", query: "app.corp.policy-fixture.com", rules: []netenv.DNSRoutingRule{{Namespace: "corp.policy-fixture.com", Priority: netenv.DNSRouteLink, Servers: []net.IP{net.ParseIP("10.20.0.54")}}, {Namespace: ".", Priority: netenv.DNSRoutePolicy, Servers: []net.IP{net.ParseIP("10.20.0.53")}}}, want: "10.20.0.53"},
		{name: "exact beats suffix at same name", query: "corp.policy-fixture.com", rules: []netenv.DNSRoutingRule{{Namespace: "corp.policy-fixture.com", Priority: netenv.DNSRoutePolicy, Servers: []net.IP{net.ParseIP("10.20.0.53")}}, {Namespace: "corp.policy-fixture.com", Exact: true, Priority: netenv.DNSRoutePolicy, Exempt: true}}, want: "192.0.2.1"},
		{name: "empty private targets stay fenced", query: "app.corp.policy-fixture.com", rules: []netenv.DNSRoutingRule{{Namespace: "corp.policy-fixture.com", Priority: netenv.DNSRoutePolicy}}},
		{name: "security requirement blocked", query: "app.corp.policy-fixture.com", rules: []netenv.DNSRoutingRule{{Namespace: "corp.policy-fixture.com", Priority: netenv.DNSRoutePolicy, Blocked: true, Servers: []net.IP{net.ParseIP("10.20.0.53")}}}},
		{name: "ignore assigned does not relax fence", query: "app.corp.policy-fixture.com", rules: []netenv.DNSRoutingRule{{Namespace: "corp.policy-fixture.com", Priority: netenv.DNSRoutePolicy, Servers: []net.IP{net.ParseIP("10.20.0.53")}}}, assigned: true},
		{name: "insecure restriction does not relax fence", query: "app.corp.policy-fixture.com", rules: []netenv.DNSRoutingRule{{Namespace: "corp.policy-fixture.com", Priority: netenv.DNSRoutePolicy, Servers: []net.IP{net.ParseIP("10.20.0.53")}}}, insecure: true},
		{name: "explicit managed strict scope wins", query: "app.corp.policy-fixture.com", rules: []netenv.DNSRoutingRule{{Namespace: "corp.policy-fixture.com", Priority: netenv.DNSRoutePolicy, Servers: []net.IP{net.ParseIP("10.20.0.53")}}}, strict: "dns://10.20.0.55?search=corp.policy-fixture.com&search-exclusive", want: "10.20.0.55"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			noInsecureProtocols = func() bool { return tc.insecure }
			noAssignedNameservers = func() bool { return tc.assigned }
			public, _, err := createResolver("dns://192.0.2.1", ServerSourceConfigured)
			if err != nil {
				t.Fatal(err)
			}
			globalResolvers = []*Resolver{public}
			if tc.strict != "" {
				r, _, err := createResolver(tc.strict, ServerSourceConfigured)
				if err != nil {
					t.Fatal(err)
				}
				globalResolvers = append(globalResolvers, r)
			}
			setScopedResolvers(globalResolvers)
			systemPolicyScopes, _, err = buildSystemDNSPolicy(globalResolvers, tc.rules)
			if err != nil {
				t.Fatal(err)
			}
			q := &Query{FQDN: tc.query + ".", QType: dns.Type(dns.TypeA)}
			if !q.check() {
				t.Fatal("invalid fixture query")
			}
			selected, _, tryAll := GetResolversInScope(context.Background(), q)
			if tryAll {
				t.Fatal("OS DNS policy must not enable unrelated fallback")
			}
			if tc.want == "" {
				if len(selected) != 0 {
					t.Fatalf("private fence relaxed: %+v", selected)
				}
			} else if len(selected) != 1 || selected[0].Info.IP.String() != tc.want {
				t.Fatalf("wrong upstreams: %v; want %s", selected, tc.want)
			}
		})
	}
}

func TestSystemDNSPolicyCacheTransitions(t *testing.T) {
	oldActive, oldGlobal, oldLocal, oldSystem, oldScopes, oldPolicy := activeResolvers, globalResolvers, localResolvers, systemResolvers, localScopes, systemPolicyScopes
	oldInsecure, oldAssigned := noInsecureProtocols, noAssignedNameservers
	t.Cleanup(func() {
		activeResolvers, globalResolvers, localResolvers, systemResolvers, localScopes, systemPolicyScopes = oldActive, oldGlobal, oldLocal, oldSystem, oldScopes, oldPolicy
		noInsecureProtocols, noAssignedNameservers = oldInsecure, oldAssigned
	})
	noInsecureProtocols = func() bool { return false }
	noAssignedNameservers = func() bool { return false }
	private := netenv.DNSRoutingRule{Namespace: "corp.policy-fixture.com", Priority: netenv.DNSRoutePolicy, Servers: []net.IP{net.ParseIP("10.20.0.53")}}
	publish := func(rules []netenv.DNSRoutingRule) []*Resolver {
		public, _, err := createResolver("dns://192.0.2.1", ServerSourceConfigured)
		if err != nil {
			t.Fatal(err)
		}
		globalResolvers = []*Resolver{public}
		setScopedResolvers(globalResolvers)
		var extra []*Resolver
		systemPolicyScopes, extra, err = buildSystemDNSPolicy(globalResolvers, rules)
		if err != nil {
			t.Fatal(err)
		}
		all := append([]*Resolver{public}, extra...)
		prepareResolverCacheContext(all, systemPolicyScopes)
		activeResolvers = make(map[string]*Resolver)
		for _, r := range all {
			activeResolvers[r.Info.ID()] = r
		}
		return all
	}
	for i, tc := range []struct {
		name          string
		before, after []netenv.DNSRoutingRule
		hit, late     bool
	}{
		{name: "introduced private route", after: []netenv.DNSRoutingRule{private}},
		{name: "removed private route", before: []netenv.DNSRoutingRule{private}},
		{name: "introduced empty private fence", after: []netenv.DNSRoutingRule{{Namespace: private.Namespace, Priority: netenv.DNSRoutePolicy}}},
		{name: "introduced blocked root", after: []netenv.DNSRoutingRule{{Namespace: ".", Blocked: true, Priority: netenv.DNSRoutePolicy}}},
		{name: "introduced exemption", before: []netenv.DNSRoutingRule{private}, after: []netenv.DNSRoutingRule{private, {Namespace: "public.corp.policy-fixture.com", Exact: true, Exempt: true, Priority: netenv.DNSRoutePolicy}}},
		{name: "unchanged policy", before: []netenv.DNSRoutingRule{private}, after: []netenv.DNSRoutingRule{private}, hit: true},
		{name: "late old public response", after: []netenv.DNSRoutingRule{private}, late: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := publish(tc.before)
			q := &Query{FQDN: fmt.Sprintf("case%d.corp.policy-fixture.com.", i), QType: dns.Type(dns.TypeA)}
			q.check()
			source := before[0]
			if len(before) > 1 {
				source = before[1]
			}
			cached := &RRCache{Domain: q.FQDN, Question: q.QType, RCode: dns.RcodeNameError, Expires: time.Now().Add(time.Hour).Unix(), Resolver: source.Info.Copy()}
			if !tc.late {
				if err := cached.Save(); err != nil {
					t.Fatal(err)
				}
			}
			publish(tc.after)
			if tc.late {
				if err := cached.Save(); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { _ = ResetCachedRecord(q.FQDN, q.QType.String()) })
			if hit := checkCache(context.Background(), q) != nil; hit != tc.hit {
				t.Fatalf("policy cache hit=%v want %v", hit, tc.hit)
			}
		})
	}
}

func TestUnsupportedSystemDNSRequirementCannotBeSilentlyOverridden(t *testing.T) {
	oldGlobal, oldLocal, oldSystem, oldScopes, oldPolicy := globalResolvers, localResolvers, systemResolvers, localScopes, systemPolicyScopes
	oldInsecure, oldAssigned := noInsecureProtocols, noAssignedNameservers
	t.Cleanup(func() {
		globalResolvers, localResolvers, systemResolvers, localScopes, systemPolicyScopes = oldGlobal, oldLocal, oldSystem, oldScopes, oldPolicy
		noInsecureProtocols, noAssignedNameservers = oldInsecure, oldAssigned
	})
	noInsecureProtocols = func() bool { return false }
	noAssignedNameservers = func() bool { return false }
	private, _, err := createResolver("dns://10.20.0.55?search=corp.policy-fixture.com&search-exclusive", ServerSourceConfigured)
	if err != nil {
		t.Fatal(err)
	}
	globalResolvers = []*Resolver{private}
	setScopedResolvers(globalResolvers)
	systemPolicyScopes, _, err = buildSystemDNSPolicy(globalResolvers, []netenv.DNSRoutingRule{{Namespace: "corp.policy-fixture.com", Priority: netenv.DNSRoutePolicy, Blocked: true}})
	if err != nil {
		t.Fatal(err)
	}
	q := &Query{FQDN: "app.corp.policy-fixture.com.", QType: dns.Type(dns.TypeA)}
	q.check()
	if selected, _, _ := GetResolversInScope(context.Background(), q); len(selected) != 0 {
		t.Fatal("strict resolver URL silently bypassed the enabled OS security requirement")
	}
}
