package resolver

import (
	"fmt"

	"github.com/packettale/agents/service/netenv"
)

type systemDNSPolicyScope struct {
	Rule      netenv.DNSRoutingRule
	Resolvers []*Resolver
}

var systemPolicyScopes []systemDNSPolicyScope // protected by resolversLock
var policyOnlyResolvers []*Resolver           // protected by resolversLock

// Build private upstreams without adding them to global fallback lists. A plain
// system upstream already present globally can be shared: its transport and
// compliance rules are identical. Reuse one fresh object per address so the
// active cache lookup never aliases two objects with different behavior.
func buildSystemDNSPolicy(global []*Resolver, rules []netenv.DNSRoutingRule) ([]systemDNSPolicyScope, []*Resolver, error) {
	canonical, err := netenv.NormalizeDNSRoutingRules(rules)
	if err != nil {
		return nil, nil, err
	}
	pool := make(map[string]*Resolver)
	for _, r := range global {
		if r.Info.Source == ServerSourceOperatingSystem && r.Info.Type == ServerTypeDNS && r.Info.Port == 53 {
			if r.SearchOnly || r.SearchExclusive {
				return nil, nil, fmt.Errorf("system DNS upstream has conflicting scope flags")
			}
			pool[r.Info.IP.String()] = r
		}
	}
	scopes := make([]systemDNSPolicyScope, 0, len(canonical))
	var extra []*Resolver
	for _, rule := range canonical {
		scope := systemDNSPolicyScope{Rule: rule}
		if !rule.Blocked && !rule.Exempt {
			for _, ip := range rule.Servers {
				key := ip.String()
				r := pool[key]
				if r == nil {
					var skip bool
					r, skip, err = createResolver("dns://"+formatIPAndPort(ip, 53), ServerSourceOperatingSystem)
					if err != nil || skip {
						return nil, nil, fmt.Errorf("cannot create scoped system DNS upstream: %w", err)
					}
					pool[key] = r
					extra = append(extra, r)
				}
				scope.Resolvers = append(scope.Resolvers, r)
			}
		}
		scopes = append(scopes, scope)
	}
	return scopes, extra, nil
}
