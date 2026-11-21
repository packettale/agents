package netenv

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/miekg/dns"
	"github.com/packettale/agents/service/network/netutils"
)

var errDNSProviderUnavailable = errors.New("system DNS provider unavailable")

// Only an absent provider permits trying another source. An active service's
// unreadable/partial policy must not be replaced with a flattened public list.
func dnsProviderInitialError(err error) error {
	var value dbus.Error
	var pointer *dbus.Error
	absent := errors.Is(err, os.ErrNotExist)
	if errors.As(err, &value) {
		absent = absent || value.Name == "org.freedesktop.DBus.Error.ServiceUnknown" || value.Name == "org.freedesktop.DBus.Error.NameHasNoOwner"
	} else if errors.As(err, &pointer) && pointer != nil {
		absent = absent || pointer.Name == "org.freedesktop.DBus.Error.ServiceUnknown" || pointer.Name == "org.freedesktop.DBus.Error.NameHasNoOwner"
	}
	if absent {
		return fmt.Errorf("%w: %w", errDNSProviderUnavailable, err)
	}
	return err
}

func networkManagerDNSConfiguration(ips []net.IP, domains, searches []string) (SystemDNSConfiguration, error) {
	var configuration SystemDNSConfiguration
	var scopes []string
	scopeOnly := false
	for _, domain := range append(append([]string{}, domains...), searches...) {
		routing := strings.HasPrefix(domain, "~")
		domain = strings.TrimPrefix(domain, "~")
		if routing && domain == "" {
			domain = "."
		}
		if domain == "" {
			continue
		}
		name := strings.ToLower(dns.Fqdn(domain))
		if !netutils.IsValidFqdn(name) {
			continue
		}
		if routing && name != "." {
			scopeOnly = true
		}
		if name != "." {
			scopes = append(scopes, strings.TrimSuffix(name, "."))
		}
		configuration.Rules = append(configuration.Rules, DNSRoutingRule{Namespace: name, Priority: DNSRouteLink})
	}
	var servers []net.IP
	for _, ip := range ips {
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.To4() == nil && ip.IsLinkLocalUnicast() {
			continue
		}
		servers = appendDNSRouteIP(servers, ip)
	}
	for _, ip := range servers {
		configuration.Nameservers = append(configuration.Nameservers, Nameserver{IP: ip, Search: append([]string(nil), scopes...), ScopeOnly: scopeOnly})
	}
	for i := range configuration.Rules {
		configuration.Rules[i].Servers = servers
	}
	rules, err := NormalizeDNSRoutingRules(configuration.Rules)
	if err != nil {
		return SystemDNSConfiguration{}, err
	}
	configuration.Rules = rules
	return configuration, nil
}

// DNSConfiguration keeps per-link routing intact. A functioning live provider
// is authoritative: flattening resolv.conf into it could make VPN-only servers
// global. The file remains the fallback for systems without these providers.
func DNSConfiguration(parent context.Context) (SystemDNSConfiguration, error) {
	if err := parent.Err(); err != nil {
		return SystemDNSConfiguration{}, err
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	return dnsConfigurationFromProviders(ctx, getDNSConfigurationFromResolvedContext, getDNSConfigurationFromDbusContext, getNameserversFromResolvconf)
}

func dnsConfigurationFromProviders(ctx context.Context,
	resolved, manager func(context.Context) (SystemDNSConfiguration, error),
	resolvconf func() ([]Nameserver, error),
) (SystemDNSConfiguration, error) {
	configuration, resolvedErr := resolved(ctx)
	if resolvedErr == nil {
		return configuration, nil
	}
	if err := ctx.Err(); err != nil {
		return configuration, err
	}
	if !errors.Is(resolvedErr, errDNSProviderUnavailable) {
		return configuration, resolvedErr
	}
	configuration, managerErr := manager(ctx)
	if managerErr == nil {
		return configuration, nil
	}
	if err := ctx.Err(); err != nil {
		return configuration, err
	}
	if !errors.Is(managerErr, errDNSProviderUnavailable) {
		return configuration, managerErr
	}
	servers, fileErr := resolvconf()
	if fileErr != nil {
		return configuration, errors.Join(resolvedErr, managerErr, fileErr)
	}
	// A resolved stub cannot supply the missing routing metadata or be used as
	// an upstream by our own intercepted resolver. Treat that provider outage
	// as an error instead of silently publishing an empty private-route table.
	for _, server := range servers {
		if server.IP.Equal(net.ParseIP("127.0.0.53")) || server.IP.Equal(net.ParseIP("127.0.0.54")) {
			return configuration, fmt.Errorf("system DNS routing provider unavailable: %w", errors.Join(resolvedErr, managerErr))
		}
	}
	return SystemDNSConfiguration{Nameservers: servers}, nil
}
