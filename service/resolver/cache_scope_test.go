package resolver

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/packettale/agents/base/database"
)

// Use the actual persisted name records and active resolver lookup. Addresses
// below are metadata; this test never sends a DNS request to these servers.
func TestDNSCacheConfigurationTransitions(t *testing.T) {
	type configuration struct {
		private   bool
		searches  []string
		reverse   bool
		exclusive bool
	}
	publicOnly := configuration{}
	office := configuration{private: true, searches: []string{"office.cache-policy-fixture.com"}}
	cases := []struct {
		name                                 string
		before, after                        configuration
		cachedPrivate, hit, legacy, lateSave bool
	}{
		{name: "unchanged public reload", before: publicOnly, after: publicOnly, hit: true},
		{name: "new private scope replaces cached public", before: publicOnly, after: office},
		{name: "private scope removed with source still active", before: office, after: configuration{private: true}, cachedPrivate: true},
		{name: "new nested scope on same source", before: office, after: configuration{private: true, searches: []string{"office.cache-policy-fixture.com", "nested.office.cache-policy-fixture.com"}}, cachedPrivate: true},
		{name: "unchanged private reload", before: office, after: office, cachedPrivate: true, hit: true},
		{name: "unchanged public fallback remains cached", before: office, after: office, hit: true},
		{name: "exclusive scope discards public fallback", before: office, after: configuration{private: true, searches: office.searches, exclusive: true}},
		{name: "exclusive scope discards previous private context", before: office, after: configuration{private: true, searches: office.searches, exclusive: true}, cachedPrivate: true},
		{name: "unchanged exclusive scope preserves private cache", before: configuration{private: true, searches: office.searches, exclusive: true}, after: configuration{private: true, searches: office.searches, exclusive: true}, cachedPrivate: true, hit: true},
		{name: "late soft response does not repopulate exclusive scope", before: office, after: configuration{private: true, searches: office.searches, exclusive: true}, lateSave: true},
		{name: "resolver priority changed", before: office, after: configuration{private: true, searches: office.searches, reverse: true}},
		{name: "scope ordering does not invalidate", before: configuration{private: true, searches: []string{"a.cache-policy-fixture.com", "b.cache-policy-fixture.com"}}, after: configuration{private: true, searches: []string{"b.cache-policy-fixture.com", "a.cache-policy-fixture.com"}}, cachedPrivate: true, hit: true},
		{name: "legacy external record refreshed once", before: publicOnly, after: publicOnly, legacy: true},
		{name: "late old response stays tied to original configuration", before: publicOnly, after: office, lateSave: true},
	}
	preserveDNSResolverState(t)
	publish := func(c configuration) []*Resolver {
		t.Helper()
		public, _, err := createResolver("dns://1.1.1.1", ServerSourceConfigured)
		if err != nil {
			t.Fatal(err)
		}
		list := []*Resolver{public}
		if c.private {
			private, _, err := createResolver("dns://10.20.0.53", ServerSourceOperatingSystem)
			if err != nil {
				t.Fatal(err)
			}
			if err := configureSearchDomains(private, c.searches, true); err != nil {
				t.Fatal(err)
			}
			private.SearchExclusive = c.exclusive
			list = append(list, private)
		}
		if c.reverse {
			list[0], list[1] = list[1], list[0]
		}
		prepareResolverCacheContext(list, nil)
		resolversLock.Lock()
		activeResolvers = make(map[string]*Resolver, len(list))
		globalResolvers = list
		systemPolicyScopes = nil
		localScopes = nil
		for _, r := range list {
			activeResolvers[r.Info.ID()] = r
			for _, search := range r.Search {
				localScopes = append(localScopes, &Scope{Domain: search, Resolvers: []*Resolver{r}})
			}
		}
		resolversLock.Unlock()
		return list
	}
	for i, tc := range cases {
		for _, rcode := range []int{dns.RcodeSuccess, dns.RcodeNameError} {
			t.Run(fmt.Sprintf("%s/rcode%d", tc.name, rcode), func(t *testing.T) {
				before := publish(tc.before)
				source := before[0]
				if tc.cachedPrivate {
					source = before[1]
				}
				q := &Query{FQDN: fmt.Sprintf("case%d-%d.office.cache-policy-fixture.com.", i, rcode), QType: dns.Type(dns.TypeA)}
				if !q.check() {
					t.Fatal("invalid query")
				}
				rr, err := dns.NewRR(q.FQDN + " 3600 IN A 203.0.113.9")
				if err != nil {
					t.Fatal(err)
				}
				info := source.Info
				if tc.legacy {
					info = &ResolverInfo{Type: info.Type, Source: info.Source, IP: info.IP, Port: info.Port, IPScope: info.IPScope}
				}
				reply := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: rcode}}
				if rcode == dns.RcodeSuccess {
					reply.Answer = []dns.RR{rr}
				}
				// Use the transport's real constructor: it copies ResolverInfo.
				cached := (&tcpQuery{Query: q}).MakeCacheRecord(reply, info)
				cached.Expires = time.Now().Add(time.Hour).Unix()
				if !tc.lateSave {
					if err := cached.Save(); err != nil {
						t.Fatal(err)
					}
					if !tc.legacy && checkCache(context.Background(), q) == nil {
						t.Fatal("original configuration rejected its own persisted cache")
					}
				}
				publish(tc.after)
				if tc.lateSave {
					if err := cached.Save(); err != nil {
						t.Fatal(err)
					}
				}
				t.Cleanup(func() { _ = ResetCachedRecord(q.FQDN, q.QType.String()) })
				got := checkCache(context.Background(), q)
				if (got != nil) != tc.hit {
					t.Fatalf("cache hit=%v want %v after DNS configuration transition", got != nil, tc.hit)
				}
				if got != nil && got.RCode != rcode {
					t.Fatalf("rcode=%d want %d", got.RCode, rcode)
				}
			})
		}
	}
}

func TestResolverCacheContextSurvivesPersistentRecord(t *testing.T) {
	r, _, err := createResolver("dns://1.1.1.1", ServerSourceConfigured)
	if err != nil {
		t.Fatal(err)
	}
	prepareResolverCacheContext([]*Resolver{r}, nil)
	if len(r.Info.CacheContext) != 64 {
		t.Fatalf("invalid context length %d", len(r.Info.CacheContext))
	}
	q := &Query{FQDN: "persistent.cache-policy-fixture.com.", QType: dns.Type(dns.TypeA)}
	q.check()
	cached := &RRCache{Domain: q.FQDN, Question: q.QType, RCode: dns.RcodeNameError, Expires: time.Now().Add(time.Hour).Unix(), Resolver: r.Info.Copy()}
	// Write through an uncached interface so this checks actual storage encoding
	// without relying on the unrelated delayed-write worker or its timing.
	stored := cached.ToNameRecord()
	stored.SetKey(makeNameRecordKey(q.FQDN, q.QType.String()))
	storage := database.NewInterface(&database.Options{Local: true, Internal: true})
	if err := storage.PutNew(stored); err != nil {
		t.Fatal(err)
	}
	loaded, err := GetRRCache(q.FQDN, q.QType)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ResetCachedRecord(q.FQDN, q.QType.String()) })
	if loaded.Resolver.CacheContext != r.Info.CacheContext {
		t.Fatal("persisted resolver lost DNS configuration context")
	}
	if loaded.Resolver.ID() != r.Info.ID() {
		t.Fatal("source identity changed on serialization")
	}
}

func BenchmarkResolverCacheContext(b *testing.B) {
	list := getConfiguredResolvers([]string{"dns://1.1.1.1", "dot://1.1.1.2?verify=cloudflare-dns.com", "dns://10.20.0.53?search=office.cache-policy-fixture.com"})
	if len(list) != 3 {
		b.Fatal("invalid benchmark resolvers")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		prepareResolverCacheContext(list, nil)
	}
}
