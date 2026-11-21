//go:build !server

package netenv

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/miekg/dns"

	"github.com/packettale/agents/service/network/netutils"
)

type resolvedDNS struct {
	Link    int32
	Family  int32
	Address []byte
}

type resolvedDNSEx struct {
	Link       int32
	Family     int32
	Address    []byte
	Port       uint16
	ServerName string
}

type resolvedDomain struct {
	Link      int32
	Domain    string
	RouteOnly bool
}

// getNameserversFromResolved discovers upstreams without depending on the stub
// listener, which may itself be intercepted by the firewall. GetAll preserves
// the per-link association between DNS servers and routing/search domains.
func getNameserversFromResolved() ([]Nameserver, error) {
	return getNameserversFromResolvedContext(context.Background())
}

func getNameserversFromResolvedContext(parent context.Context) ([]Nameserver, error) {
	configuration, err := getDNSConfigurationFromResolvedContext(parent)
	return configuration.Nameservers, err
}

func getDNSConfigurationFromResolvedContext(parent context.Context) (SystemDNSConfiguration, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return SystemDNSConfiguration{}, dnsProviderInitialError(err)
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	var properties map[string]dbus.Variant
	err = conn.Object("org.freedesktop.resolve1", "/org/freedesktop/resolve1").
		CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", dbus.FlagNoAutoStart,
			"org.freedesktop.resolve1.Manager").Store(&properties)
	if err != nil {
		return SystemDNSConfiguration{}, fmt.Errorf("read systemd-resolved DNS configuration: %w", dnsProviderInitialError(err))
	}
	configuration, err := resolvedDNSConfiguration(properties)
	if err != nil {
		return configuration, err
	}
	if err := validateResolvedSecurityProperties(properties); err != nil {
		return configuration, err
	}
	var servers []resolvedDNS
	if err := properties["DNS"].Store(&servers); err != nil {
		return configuration, err
	}
	defaults := make(map[int32]bool)
	links := make(map[int32]map[string]dbus.Variant)
	var domains []resolvedDomain
	if err := properties["Domains"].Store(&domains); err != nil {
		return configuration, err
	}
	// A transiently unavailable upstream must not erase the link's namespace.
	for _, domain := range domains {
		servers = append(servers, resolvedDNS{Link: domain.Link})
	}
	for _, server := range servers {
		if server.Link <= 0 {
			continue
		}
		if _, read := defaults[server.Link]; read {
			continue
		}
		link, err := resolvedLinkProperties(ctx, conn, server.Link)
		if err != nil {
			return configuration, err
		}
		var enabled bool
		if err := link["DefaultRoute"].Store(&enabled); err != nil {
			return configuration, err
		}
		defaults[server.Link] = enabled
		links[server.Link] = link
	}
	return resolvedDNSConfigurationWithPolicies(properties, defaults, links)
}

func resolvedNameservers(properties map[string]dbus.Variant) ([]Nameserver, error) {
	configuration, err := resolvedDNSConfiguration(properties)
	return configuration.Nameservers, err
}

func resolvedDNSConfiguration(properties map[string]dbus.Variant) (SystemDNSConfiguration, error) {
	return resolvedDNSConfigurationWithDefaultRoutes(properties, nil)
}

func resolvedDNSConfigurationWithDefaultRoutes(properties map[string]dbus.Variant, defaults map[int32]bool) (SystemDNSConfiguration, error) {
	return resolvedDNSConfigurationWithPolicies(properties, defaults, nil)
}

func resolvedDNSConfigurationWithPolicies(properties map[string]dbus.Variant, defaults map[int32]bool, links map[int32]map[string]dbus.Variant) (SystemDNSConfiguration, error) {
	var configuration SystemDNSConfiguration
	if properties["DNS"].Value() == nil || properties["Domains"].Value() == nil {
		return configuration, errors.New("systemd-resolved DNS/domain properties missing")
	}
	var servers []resolvedDNS
	if err := properties["DNS"].Store(&servers); err != nil {
		return configuration, fmt.Errorf("decode systemd-resolved DNS: %w", err)
	}
	var domains []resolvedDomain
	if err := properties["Domains"].Store(&domains); err != nil {
		return configuration, fmt.Errorf("decode systemd-resolved domains: %w", err)
	}
	if len(domains) > maxDNSRoutingRules || len(servers) > maxDNSRoutingRules*maxDNSRouteServers {
		return configuration, errors.New("systemd-resolved DNS configuration exceeds size limit")
	}
	searches := make(map[int32][]string)
	scopeOnly := make(map[int32]bool)
	for _, domain := range domains {
		if netutils.IsValidFqdn(strings.ToLower(dns.Fqdn(domain.Domain))) && domain.Domain != "." {
			searches[domain.Link] = append(searches[domain.Link], domain.Domain)
		}
		if domain.RouteOnly && domain.Domain != "." {
			scopeOnly[domain.Link] = true
		}
	}
	for link, enabled := range defaults {
		scopeOnly[link] = !enabled
	}
	blocked := make(map[int32]bool)
	unsupportedPort := make(map[int32]bool)
	if properties["DNSEx"].Value() != nil {
		var extended []resolvedDNSEx
		if err := properties["DNSEx"].Store(&extended); err != nil {
			return configuration, fmt.Errorf("decode systemd-resolved extended DNS metadata: %w", err)
		}
		if len(extended) > maxDNSRoutingRules*maxDNSRouteServers {
			return configuration, errors.New("systemd-resolved extended DNS configuration exceeds size limit")
		}
		for _, server := range extended {
			unsupportedPort[server.Link] = unsupportedPort[server.Link] || server.Port != 0 && server.Port != 53
		}
	}
	// Link properties already contain systemd-resolved's effective inherited
	// modes. The core's plain system upstreams cannot implement required TLS
	// or validate DNSSEC, so preserve these requirements as visible fences.
	for _, server := range servers {
		security := properties
		if link, ok := links[server.Link]; ok {
			security = link
		}
		blocked[server.Link] = unsupportedPort[server.Link] || security["DNSSEC"].Value() == "yes" || security["DNSOverTLS"].Value() == "yes"
	}
	for _, domain := range domains {
		security := properties
		if link, ok := links[domain.Link]; ok {
			security = link
		}
		blocked[domain.Link] = unsupportedPort[domain.Link] || security["DNSSEC"].Value() == "yes" || security["DNSOverTLS"].Value() == "yes"
	}
	serversByLink := make(map[int32][]net.IP)
	for _, server := range servers {
		// These families are Linux AF_INET and AF_INET6 (D-Bus API values).
		if !(server.Family == 2 && len(server.Address) == net.IPv4len ||
			server.Family == 10 && len(server.Address) == net.IPv6len) {
			continue
		}
		ip := net.IP(server.Address)
		if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() ||
			(server.Family == 10 && ip.IsLinkLocalUnicast()) {
			continue
		}
		ip = append(net.IP(nil), ip...)
		configuration.Nameservers = append(configuration.Nameservers, Nameserver{
			IP: ip, Search: append([]string(nil), searches[server.Link]...), ScopeOnly: scopeOnly[server.Link] || blocked[server.Link],
		})
		serversByLink[server.Link] = appendDNSRouteIP(serversByLink[server.Link], ip)
	}
	for _, domain := range domains {
		name := strings.ToLower(dns.Fqdn(domain.Domain))
		if domain.Domain == "" || !netutils.IsValidFqdn(name) {
			continue
		}
		// Keep root and unavailable-link routes even when no usable upstream
		// survived filtering. Losing such a route would allow public fallback.
		configuration.Rules = append(configuration.Rules, DNSRoutingRule{
			Namespace: name, Servers: serversByLink[domain.Link], Priority: DNSRouteLink, Blocked: blocked[domain.Link],
		})
	}
	for link, required := range blocked {
		if required && (link == 0 || defaults[link]) {
			configuration.Rules = append(configuration.Rules, DNSRoutingRule{
				Namespace: ".", Servers: serversByLink[link], Priority: DNSRouteLink, Blocked: true,
			})
		}
	}
	rules, err := NormalizeDNSRoutingRules(configuration.Rules)
	if err != nil {
		return SystemDNSConfiguration{}, err
	}
	configuration.Rules = rules
	return configuration, nil
}

func resolvedLinkDefaultRoute(ctx context.Context, conn *dbus.Conn, index int32) (bool, error) {
	properties, err := resolvedLinkProperties(ctx, conn, index)
	if err != nil {
		return false, err
	}
	var enabled bool
	err = properties["DefaultRoute"].Store(&enabled)
	return enabled, err
}

func resolvedLinkProperties(ctx context.Context, conn *dbus.Conn, index int32) (map[string]dbus.Variant, error) {
	// Link paths are encoded by the service and must not be reconstructed
	// from an interface index. Ask the manager for the actual object path.
	var path dbus.ObjectPath
	if err := conn.Object("org.freedesktop.resolve1", "/org/freedesktop/resolve1").
		CallWithContext(ctx, "org.freedesktop.resolve1.Manager.GetLink", dbus.FlagNoAutoStart, index).Store(&path); err != nil {
		return nil, fmt.Errorf("read systemd-resolved link path: %w", err)
	}
	if !path.IsValid() || path == "/" {
		return nil, errors.New("invalid systemd-resolved link path")
	}
	var properties map[string]dbus.Variant
	err := conn.Object("org.freedesktop.resolve1", path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", dbus.FlagNoAutoStart, "org.freedesktop.resolve1.Link").Store(&properties)
	if err != nil {
		return nil, fmt.Errorf("read systemd-resolved link routing: %w", err)
	}
	if err := validateResolvedSecurityProperties(properties); err != nil {
		return nil, err
	}
	var enabled bool
	if properties["DefaultRoute"].Value() == nil {
		return nil, errors.New("systemd-resolved link routing property missing")
	}
	if err := properties["DefaultRoute"].Store(&enabled); err != nil {
		return nil, fmt.Errorf("decode systemd-resolved link routing: %w", err)
	}
	return properties, nil
}

func validateResolvedSecurityProperties(properties map[string]dbus.Variant) error {
	for key, modes := range map[string][]string{
		"DNSSEC":     {"no", "yes", "allow-downgrade"},
		"DNSOverTLS": {"no", "yes", "opportunistic"},
	} {
		var mode string
		if properties[key].Value() == nil {
			return fmt.Errorf("systemd-resolved %s mode missing", key)
		}
		if err := properties[key].Store(&mode); err != nil {
			return fmt.Errorf("read systemd-resolved %s mode: %w", key, err)
		}
		valid := false
		for _, allowed := range modes {
			valid = valid || mode == allowed
		}
		if !valid {
			return fmt.Errorf("unsupported systemd-resolved %s mode", key)
		}
	}
	return nil
}
