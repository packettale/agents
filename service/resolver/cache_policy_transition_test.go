package resolver

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/packettale/agents/service/netenv"
)

func TestResolverFailureDoesNotReturnBackupAcrossPolicyChange(t *testing.T) {
	preserveDNSResolverState(t)
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "unchanged policy retains backup", true: "new policy rejects old backup"}[changed], func(t *testing.T) {
			loadResolversWithSystemDNS(func(context.Context) (netenv.SystemDNSConfiguration, error) {
				return netenv.SystemDNSConfiguration{}, nil
			})
			q := &Query{FQDN: netenv.DNSTestDomain, QType: dns.Type(dns.TypeA)}
			if !q.check() {
				t.Fatal("invalid fixture query")
			}
			old := &RRCache{Domain: q.FQDN, Question: q.QType, RCode: dns.RcodeSuccess,
				Expires: time.Now().Add(-time.Minute).Unix(), Resolver: globalResolvers[0].Info.Copy()}
			var once sync.Once
			called := false
			fail := func() {
				once.Do(func() {
					called = true
					if changed {
						loadResolversWithSystemDNS(func(context.Context) (netenv.SystemDNSConfiguration, error) {
							return netenv.SystemDNSConfiguration{Rules: []netenv.DNSRoutingRule{{Namespace: ".", Priority: netenv.DNSRoutePolicy, Blocked: true}}}, nil
						})
					}
				})
			}
			for _, resolver := range globalResolvers {
				resolver.Conn = &scopeResponseConn{err: errors.New("controlled query failure"), onQuery: fail}
			}
			got, err := resolveAndCache(context.Background(), q, old)
			if !called {
				t.Fatal("fixture query never reached its in-memory transport")
			}
			if changed && (got != nil || err == nil) {
				t.Fatalf("previous-policy backup escaped: result=%v error=%v", got, err)
			}
			if !changed && (got != old || err != nil || !old.IsBackup) {
				t.Fatalf("ordinary backup behavior changed: result=%v error=%v", got, err)
			}
		})
	}
}
