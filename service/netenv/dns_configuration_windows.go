package netenv

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/packettale/agents/service/network/netutils"
	"golang.org/x/sys/windows"
)

func DNSConfiguration(ctx context.Context) (SystemDNSConfiguration, error) {
	configuration, _, err := readWindowsSystemDNSConfiguration(ctx)
	return configuration, err
}

func readWindowsSystemDNSConfiguration(ctx context.Context) (SystemDNSConfiguration, []string, error) {
	var configuration SystemDNSConfiguration
	if err := ctx.Err(); err != nil {
		return configuration, nil, err
	}
	data, err := readWindowsDNSConfiguration()
	if err != nil {
		return configuration, nil, err
	}
	rows, err := readWindowsRoutes()
	if err != nil {
		return configuration, nil, err
	}
	extra := append(data.extra, windowsDefaultRouteFingerprint(data.adapters, rows)...)
	primary := defaultInterfaceFromWindows(data.adapters, rows, data.globalSuffixes)
	configuration.Nameservers = nameserversFromWindowsDefault(primary)
	if !FollowSystemDNSRouting() {
		return configuration, extra, nil
	}
	linkRules, err := windowsLinkDNSRules(data.adapters)
	if err != nil {
		return configuration, extra, err
	}
	policy, err := readWindowsNRPTRules(ctx)
	if err != nil {
		return configuration, extra, fmt.Errorf("read effective Windows DNS policy: %w", err)
	}
	configuration.Rules, err = NormalizeDNSRoutingRules(append(linkRules, policy...))
	return configuration, extra, err
}

func windowsLinkDNSRules(adapters *windows.IpAdapterAddresses) ([]DNSRoutingRule, error) {
	var rules []DNSRoutingRule
	for adapter := adapters; adapter != nil; adapter = adapter.Next {
		if adapter.OperStatus != windows.IfOperStatusUp || adapter.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK {
			continue
		}
		var servers []net.IP
		for server := adapter.FirstDnsServerAddress; server != nil; server = server.Next {
			ip := server.Address.IP()
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.To4() == nil && ip.IsLinkLocalUnicast() {
				continue
			}
			servers = appendDNSRouteIP(servers, ip)
		}
		for _, suffix := range windowsAdapterScopes(adapter) {
			if suffix == "" {
				continue
			}
			name := strings.ToLower(dns.Fqdn(suffix))
			if !netutils.IsValidFqdn(name) {
				continue
			}
			rules = append(rules, DNSRoutingRule{Namespace: name, Servers: servers, Priority: DNSRouteLink})
		}
	}
	return NormalizeDNSRoutingRules(rules)
}
