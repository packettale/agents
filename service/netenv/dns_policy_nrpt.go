package netenv

import (
	"fmt"
	"net"
	"strings"
)

// windowsDNSPolicy contains only the effective OS fields relevant to routing.
// Security requirements are retained as a fence rather than downgraded to plain
// DNS; this resolver does not implement DirectAccess, IPsec or DNSSEC validation.
type windowsDNSPolicy struct {
	Namespace      string
	NameServers    []string
	DirectAccess   bool
	DNSSECRequired bool
	IPsecRequired  bool
}

func windowsDNSPolicyRules(records []windowsDNSPolicy) ([]DNSRoutingRule, error) {
	if len(records) > maxDNSRoutingRules {
		return nil, fmt.Errorf("too many effective NRPT policies")
	}
	rules := make([]DNSRoutingRule, 0, len(records))
	for _, record := range records {
		rule := DNSRoutingRule{Namespace: record.Namespace, Exact: true, Priority: DNSRoutePolicy, Blocked: record.DirectAccess || record.DNSSECRequired || record.IPsecRequired}
		if rule.Namespace == "." {
			rule.Exact = false
		} else if strings.HasPrefix(rule.Namespace, ".") {
			rule.Namespace = strings.TrimPrefix(rule.Namespace, ".")
			rule.Exact = false
			if strings.HasPrefix(rule.Namespace, ".") {
				return nil, fmt.Errorf("invalid effective NRPT namespace")
			}
		}
		if len(record.NameServers) > maxDNSRouteServers {
			return nil, fmt.Errorf("too many effective NRPT servers")
		}
		for _, server := range record.NameServers {
			ip := net.ParseIP(server)
			if ip == nil {
				rule.Blocked = true
				continue
			}
			rule.Servers = append(rule.Servers, ip)
		}
		rule.Exempt = len(record.NameServers) == 0 && !rule.Blocked
		rules = append(rules, rule)
	}
	return NormalizeDNSRoutingRules(rules)
}
