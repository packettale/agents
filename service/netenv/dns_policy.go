package netenv

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"
	"github.com/packettale/agents/service/network/netutils"
)

const (
	DNSRouteLink       uint8 = 1
	DNSRoutePolicy     uint8 = 2
	maxDNSRoutingRules       = 1000
	maxDNSRouteServers       = 32
)

// DNSRoutingRule binds a namespace to OS-selected upstreams. Exact distinguishes
// a host exception from a suffix; "." is a default route. An empty server list
// fences an unavailable namespace. Exempt resumes ordinary configured DNS and
// Blocked records an OS requirement the current transport cannot satisfy.
type DNSRoutingRule struct {
	Namespace string
	Exact     bool
	Servers   []net.IP
	Exempt    bool
	Blocked   bool
	Priority  uint8
}

// SystemDNSConfiguration is assembled on configuration reload, never per query.
// A caller publishes Nameservers and Rules together with a fresh cache context.
type SystemDNSConfiguration struct {
	Nameservers []Nameserver
	Rules       []DNSRoutingRule
}

// NormalizeDNSRoutingRules owns all returned slices and IPs. It retains empty
// fences, canonicalizes namespace order and merges equally specific link peers.
// Server order remains significant because it determines failover order.
func NormalizeDNSRoutingRules(input []DNSRoutingRule) ([]DNSRoutingRule, error) {
	if len(input) > maxDNSRoutingRules {
		return nil, fmt.Errorf("system DNS policy exceeds %d rules", maxDNSRoutingRules)
	}
	result := make([]DNSRoutingRule, 0, len(input))
	type key struct {
		namespace string
		exact     bool
		priority  uint8
	}
	positions := make(map[key]int, len(input))
	for _, original := range input {
		rule := original
		if rule.Namespace == "" || rule.Namespace != strings.TrimSpace(rule.Namespace) || strings.HasPrefix(rule.Namespace, ".") && rule.Namespace != "." {
			return nil, fmt.Errorf("invalid system DNS namespace")
		}
		rule.Namespace = dns.Fqdn(strings.ToLower(rule.Namespace))
		if !netutils.IsValidFqdn(rule.Namespace) || strings.ContainsAny(rule.Namespace, "*\\ ") || rule.Exact && rule.Namespace == "." {
			return nil, fmt.Errorf("invalid system DNS namespace")
		}
		if rule.Priority != DNSRouteLink && rule.Priority != DNSRoutePolicy {
			return nil, fmt.Errorf("invalid system DNS rule priority")
		}
		if len(rule.Servers) > maxDNSRouteServers {
			return nil, fmt.Errorf("system DNS rule exceeds %d servers", maxDNSRouteServers)
		}
		if rule.Exempt && (len(rule.Servers) > 0 || rule.Blocked) {
			return nil, fmt.Errorf("conflicting system DNS rule modes")
		}
		rule.Servers = nil
		for _, ip := range original.Servers {
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.Equal(net.IPv4bcast) || ip.To4() == nil && ip.IsLinkLocalUnicast() {
				rule.Blocked = true
				continue
			}
			canonical := ip.To4()
			if canonical == nil {
				canonical = ip.To16()
			}
			if canonical == nil {
				rule.Blocked = true
				continue
			}
			rule.Servers = appendDNSRouteIP(rule.Servers, canonical)
		}
		k := key{rule.Namespace, rule.Exact, rule.Priority}
		if at, exists := positions[k]; exists {
			current := &result[at]
			if current.Exempt != rule.Exempt {
				current.Blocked = true
				current.Exempt = false
			}
			current.Blocked = current.Blocked || rule.Blocked
			for _, ip := range rule.Servers {
				current.Servers = appendDNSRouteIP(current.Servers, ip)
			}
			if len(current.Servers) > maxDNSRouteServers {
				return nil, fmt.Errorf("merged system DNS rule exceeds %d servers", maxDNSRouteServers)
			}
		} else {
			positions[k] = len(result)
			result = append(result, rule)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i], result[j]
		if a.Priority != b.Priority {
			return a.Priority > b.Priority
		}
		if len(a.Namespace) != len(b.Namespace) {
			return len(a.Namespace) > len(b.Namespace)
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Exact && !b.Exact
	})
	return result, nil
}

func appendDNSRouteIP(list []net.IP, ip net.IP) []net.IP {
	for _, present := range list {
		if present.Equal(ip) {
			return list
		}
	}
	return append(list, append(net.IP(nil), ip...))
}
