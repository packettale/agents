package resolver

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/packettale/agents/base/config"
	"github.com/packettale/agents/service/netenv"
	"github.com/miekg/dns"
)

func setScopedResolvers(resolvers []*Resolver) {
	systemResolvers, localResolvers, localScopes = buildScopedResolvers(resolvers)
}

func preserveDNSResolverState(t *testing.T) {
	t.Helper()
	resolversLock.Lock()
	oldGlobal, oldLocal, oldSystem, oldScopes, oldActive, oldPolicy := globalResolvers, localResolvers, systemResolvers, localScopes, activeResolvers, systemPolicyScopes
	oldConfig := currentResolverConfig
	oldBootstrap, oldExtra := resolverInitDomains, policyOnlyResolvers
	oldMulticast := mDNSResolvers
	resolversLock.Unlock()
	disabled := module.isDisabled.Load()
	t.Cleanup(func() {
		resolversLock.Lock()
		globalResolvers, localResolvers, systemResolvers, localScopes, activeResolvers, systemPolicyScopes = oldGlobal, oldLocal, oldSystem, oldScopes, oldActive, oldPolicy
		currentResolverConfig = oldConfig
		resolverInitDomains, policyOnlyResolvers = oldBootstrap, oldExtra
		mDNSResolvers = oldMulticast
		module.states.Remove("system-dns-policy-unavailable")
		module.states.Remove("system-dns-policy-unsupported")
		module.isDisabled.Store(disabled)
		resolversLock.Unlock()
	})
}

func TestDNSReloadDoesNotBlockExistingResolverSelection(t *testing.T) {
	preserveDNSResolverState(t)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	reader := func(ctx context.Context) (netenv.SystemDNSConfiguration, error) {
		close(entered)
		select {
		case <-release:
			return netenv.SystemDNSConfiguration{}, nil
		case <-ctx.Done():
			return netenv.SystemDNSConfiguration{}, ctx.Err()
		}
	}
	go func() { loadResolversWithSystemDNS(reader); close(done) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		close(release)
		<-done
		t.Fatal("reload did not reach OS reader")
	}
	selected := make(chan struct{})
	go func() {
		q := &Query{FQDN: "unrelated.policy-fixture.com.", QType: dns.Type(dns.TypeA)}
		q.check()
		GetResolversInScope(context.Background(), q)
		close(selected)
	}()
	var blocked bool
	select {
	case <-selected:
	case <-time.After(150 * time.Millisecond):
		blocked = true
	}
	close(release)
	<-done
	<-selected
	if blocked {
		t.Fatal("slow OS metadata read held the DNS query lock")
	}
}

func TestDNSReloadPublishesSystemPolicyAndFailureFence(t *testing.T) {
	preserveDNSResolverState(t)
	for _, tc := range []struct {
		name    string
		readErr error
		want    string
	}{
		{name: "healthy scoped policy", want: "10.20.0.53"},
		{name: "failed OS policy read", readErr: errors.New("controlled policy read failure")},
		{name: "recovered OS policy read", want: "10.20.0.53"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			loadResolversWithSystemDNS(func(context.Context) (netenv.SystemDNSConfiguration, error) {
				return netenv.SystemDNSConfiguration{Rules: []netenv.DNSRoutingRule{{Namespace: "corp.policy-fixture.com", Priority: netenv.DNSRoutePolicy, Servers: []net.IP{net.ParseIP("10.20.0.53")}}}}, tc.readErr
			})
			q := &Query{FQDN: "app.corp.policy-fixture.com.", QType: dns.Type(dns.TypeA)}
			q.check()
			selected, _, _ := GetResolversInScope(context.Background(), q)
			if tc.want == "" {
				if len(selected) != 0 {
					t.Fatal("failed native policy read silently fell back to unrelated DNS")
				}
			} else if len(selected) != 1 || selected[0].Info.IP.String() != tc.want {
				t.Fatalf("new OS scope not published: %v", selected)
			}
		})
	}
}

func TestEmptyCustomDNSKeepsSystemResolversAndFiltering(t *testing.T) {
	preserveDNSResolverState(t)
	previous := append([]string(nil), configuredNameServers()...)
	if err := config.SetConfigOption(CfgOptionNameServersKey, []string{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = config.SetConfigOption(CfgOptionNameServersKey, previous) })
	loadResolversWithSystemDNS(func(context.Context) (netenv.SystemDNSConfiguration, error) {
		return netenv.SystemDNSConfiguration{Nameservers: []netenv.Nameserver{{IP: net.ParseIP("10.20.0.53"), Search: []string{"corp.test."}}}}, nil
	})
	if module.IsDisabled() {
		t.Fatal("empty custom list disabled DNS interception/filtering")
	}
	resolversLock.Lock()
	defer resolversLock.Unlock()
	if len(globalResolvers) != 1 || globalResolvers[0].Info.IP.String() != "10.20.0.53" {
		t.Fatalf("expected only DHCP resolver, got %v", globalResolvers)
	}
}
