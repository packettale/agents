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

func TestMulticastCacheHonorsPolicyTransitions(t *testing.T) {
	preserveDNSResolverState(t)
	oldMulticast := noMulticastDNS
	noMulticastDNS = func() bool { return false }
	t.Cleanup(func() { noMulticastDNS = oldMulticast })
	for i, tc := range []struct {
		name string
		rule *netenv.DNSRoutingRule
		late bool
		hit  bool
	}{
		{name: "unchanged multicast routing", hit: true},
		{name: "blocked local suffix", rule: &netenv.DNSRoutingRule{Namespace: "local.", Priority: netenv.DNSRoutePolicy, Blocked: true}},
		{name: "blocked root", rule: &netenv.DNSRoutingRule{Namespace: ".", Priority: netenv.DNSRoutePolicy, Blocked: true}},
		{name: "private unicast local suffix", rule: &netenv.DNSRoutingRule{Namespace: "local.", Priority: netenv.DNSRoutePolicy, Servers: []net.IP{net.ParseIP("10.20.0.53")}}},
		{name: "late blocked response", rule: &netenv.DNSRoutingRule{Namespace: "local.", Priority: netenv.DNSRoutePolicy, Blocked: true}, late: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			loadResolversWithSystemDNS(func(context.Context) (netenv.SystemDNSConfiguration, error) {
				return netenv.SystemDNSConfiguration{}, nil
			})
			q := &Query{FQDN: fmt.Sprintf("multicast-cache-%d.fixture.local.", i), QType: dns.Type(dns.TypeA)}
			if !q.check() {
				t.Fatal("invalid fixture query")
			}
			selected, _, _ := GetResolversInScope(context.Background(), q)
			var source *ResolverInfo
			for _, resolver := range selected {
				if resolver.Info.Type == ServerTypeMDNS {
					source = resolver.Info.Copy()
				}
			}
			if source == nil {
				t.Fatal("ordinary multicast routing was unavailable")
			}
			cached := &RRCache{Domain: q.FQDN, Question: q.QType, RCode: dns.RcodeSuccess, Expires: time.Now().Add(time.Hour).Unix(), Resolver: source}
			t.Cleanup(func() { _ = ResetCachedRecord(q.FQDN, q.QType.String()) })
			if !tc.late {
				if err := cached.Save(); err != nil {
					t.Fatal(err)
				}
				if checkCache(context.Background(), q) == nil {
					t.Fatal("ordinary multicast cache stopped working")
				}
			}
			loadResolversWithSystemDNS(func(context.Context) (netenv.SystemDNSConfiguration, error) {
				configuration := netenv.SystemDNSConfiguration{}
				if tc.rule != nil {
					configuration.Rules = []netenv.DNSRoutingRule{*tc.rule}
				}
				return configuration, nil
			})
			if tc.late {
				if err := cached.Save(); err != nil {
					t.Fatal(err)
				}
			}
			if hit := checkCache(context.Background(), q) != nil; hit != tc.hit {
				t.Fatalf("multicast cache hit=%v, want %v", hit, tc.hit)
			}
		})
	}
}

func TestMulticastQueuedAndDelayedResponsesDoNotCrossGenerations(t *testing.T) {
	preserveDNSResolverState(t)
	oldMulticast := noMulticastDNS
	noMulticastDNS = func() bool { return false }
	t.Cleanup(func() { noMulticastDNS = oldMulticast })
	loadResolversWithSystemDNS(func(context.Context) (netenv.SystemDNSConfiguration, error) {
		return netenv.SystemDNSConfiguration{}, nil
	})
	oldSource := currentMulticastResolverInfo()
	loadResolversWithSystemDNS(func(context.Context) (netenv.SystemDNSConfiguration, error) {
		return netenv.SystemDNSConfiguration{Nameservers: []netenv.Nameserver{{IP: net.ParseIP("10.20.0.53")}}}, nil
	})
	currentSource := currentMulticastResolverInfo()
	if oldSource.CacheContext == currentSource.CacheContext {
		t.Fatal("fixture did not change DNS generation")
	}
	oldResponse, currentResponse := make(chan *RRCache, 1), make(chan *RRCache, 1)
	names := []string{"queued-generation.fixture.local.", "late-generation.fixture.local.", "current-generation.fixture.local."}
	for _, name := range names {
		_ = ResetCachedRecord(name, "A")
		t.Cleanup(func() { _ = ResetCachedRecord(name, "A") })
	}
	questionsLock.Lock()
	previousOld, previousCurrent := questions[63001], questions[63002]
	questions[63001] = &savedQuestion{question: dns.Question{Name: names[1], Qtype: dns.TypeA, Qclass: dns.ClassINET}, expires: time.Now().Add(time.Minute), response: oldResponse, resolver: oldSource}
	questions[63002] = &savedQuestion{question: dns.Question{Name: names[2], Qtype: dns.TypeA, Qclass: dns.ClassINET}, expires: time.Now().Add(time.Minute), response: currentResponse, resolver: currentSource}
	questionsLock.Unlock()
	t.Cleanup(func() {
		questionsLock.Lock()
		for id, value := range map[uint16]*savedQuestion{63001: previousOld, 63002: previousCurrent} {
			if value == nil {
				delete(questions, id)
			} else {
				questions[id] = value
			}
		}
		questionsLock.Unlock()
	})
	messages := make(chan *mdnsPacket, 3)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- handleMDNSMessages(ctx, messages) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("multicast handler did not stop")
		}
	})
	for i, name := range names {
		message := &dns.Msg{MsgHdr: dns.MsgHdr{Id: uint16(63000 + i), Response: true}, Question: []dns.Question{{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}}, Answer: []dns.RR{
			&dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}, A: net.ParseIP("192.0.2.90")},
		}}
		source := currentSource
		if i == 0 {
			source = oldSource
		} // Received before publication, processed after it.
		messages <- &mdnsPacket{message: message, resolver: source}
	}
	select {
	case record := <-currentResponse:
		if record.Resolver.CacheContext != currentSource.CacheContext {
			t.Fatal("current response lost its generation")
		}
	case <-time.After(time.Second):
		t.Fatal("ordinary multicast response did not complete")
	}
	if len(oldResponse) != 0 {
		t.Error("delayed response crossed its query's DNS generation")
	}
	for _, name := range names[:2] {
		if _, err := GetRRCache(name, dns.Type(dns.TypeA)); err == nil {
			t.Errorf("older multicast response was admitted for %s", name)
		}
	}
	if _, err := GetRRCache(names[2], dns.Type(dns.TypeA)); err != nil {
		t.Errorf("ordinary multicast response was not cached: %v", err)
	}
}
