package netenv

import (
	"fmt"
	"net"
	"sort"

	"github.com/godbus/dbus/v5"
)

type networkManagerDNSSettings struct {
	Servers  []net.IP
	Domains  []string
	Priority int32
	Global   bool
}

func networkManagerDNSProperties(properties map[string]dbus.Variant) (SystemDNSConfiguration, error) {
	var mode string
	var raw []map[string]dbus.Variant
	if properties["Mode"].Value() == nil || properties["Configuration"].Value() == nil {
		return SystemDNSConfiguration{}, fmt.Errorf("NetworkManager DNS policy properties missing")
	}
	if err := properties["Mode"].Store(&mode); err != nil {
		return SystemDNSConfiguration{}, fmt.Errorf("decode NetworkManager DNS mode: %w", err)
	}
	if err := properties["Configuration"].Store(&raw); err != nil {
		return SystemDNSConfiguration{}, fmt.Errorf("decode NetworkManager DNS configurations: %w", err)
	}
	if len(raw) > maxDNSRoutingRules {
		return SystemDNSConfiguration{}, fmt.Errorf("NetworkManager DNS configuration exceeds size limit")
	}
	entries := make([]networkManagerDNSSettings, 0, len(raw))
	for _, properties := range raw {
		var entry networkManagerDNSSettings
		var nameservers []string
		if properties["priority"].Value() == nil || properties["nameservers"].Value() == nil {
			return SystemDNSConfiguration{}, fmt.Errorf("NetworkManager DNS entry properties missing")
		}
		if err := properties["priority"].Store(&entry.Priority); err != nil {
			return SystemDNSConfiguration{}, fmt.Errorf("decode NetworkManager DNS priority: %w", err)
		}
		if err := properties["nameservers"].Store(&nameservers); err != nil {
			return SystemDNSConfiguration{}, fmt.Errorf("decode NetworkManager nameservers: %w", err)
		}
		if properties["domains"].Value() != nil {
			if err := properties["domains"].Store(&entry.Domains); err != nil {
				return SystemDNSConfiguration{}, fmt.Errorf("decode NetworkManager DNS domains: %w", err)
			}
		}
		if len(nameservers) > maxDNSRouteServers || len(entry.Domains) > maxDNSRoutingRules {
			return SystemDNSConfiguration{}, fmt.Errorf("NetworkManager DNS entry exceeds size limit")
		}
		// Global DNS entries have neither interface nor VPN metadata. A removed
		// interface can lack its name but still has the VPN boolean in NM's export.
		entry.Global = properties["interface"].Value() == nil && properties["vpn"].Value() == nil
		for _, address := range nameservers {
			ip := net.ParseIP(address)
			if ip == nil {
				return SystemDNSConfiguration{}, fmt.Errorf("NetworkManager DNS transport/address is unsupported")
			}
			entry.Servers = append(entry.Servers, ip)
		}
		entries = append(entries, entry)
	}
	return networkManagerPriorityConfiguration(mode, entries)
}

func networkManagerPriorityConfiguration(mode string, entries []networkManagerDNSSettings) (SystemDNSConfiguration, error) {
	if len(entries) > maxDNSRoutingRules {
		return SystemDNSConfiguration{}, fmt.Errorf("NetworkManager DNS configuration exceeds size limit")
	}
	entries = append([]networkManagerDNSSettings(nil), entries...)
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Priority < entries[j].Priority })
	// A global wildcard overrides interface configuration in NetworkManager.
	globalDefault := false
	for _, entry := range entries {
		globalDefault = globalDefault || entry.Global && len(entry.Domains) == 0
	}
	if globalDefault {
		filtered := entries[:0]
		for _, entry := range entries {
			if entry.Global {
				filtered = append(filtered, entry)
			}
		}
		entries = filtered
	}
	negative := len(entries) > 0 && entries[0].Priority < 0
	if mode == "default" && negative {
		minimum := entries[0].Priority
		filtered := entries[:0]
		for _, entry := range entries {
			if entry.Priority == minimum {
				filtered = append(filtered, entry)
			}
		}
		entries = filtered
	}
	var result SystemDNSConfiguration
	type candidate struct {
		rule     DNSRoutingRule
		priority int32
		global   bool
	}
	var candidates []candidate
	best := make(map[string]candidate)
	for _, entry := range entries {
		domains := entry.Domains
		if entry.Global && len(domains) == 0 {
			domains = []string{"~."}
		}
		configuration, err := networkManagerDNSConfiguration(entry.Servers, domains, nil)
		if err != nil {
			return result, err
		}
		result.Nameservers = append(result.Nameservers, configuration.Nameservers...)
		for _, rule := range configuration.Rules {
			current := candidate{rule: rule, priority: entry.Priority, global: entry.Global}
			previous, exists := best[rule.Namespace]
			if !exists || current.global && !previous.global || current.global == previous.global && current.priority < previous.priority {
				best[rule.Namespace] = current
			}
			candidates = append(candidates, current)
		}
	}
	if mode == "none" {
		return result, errDNSProviderUnavailable
	}
	if mode == "dnsmasq" {
		// Configuration exports raw domains, not the implicit default/reverse
		// routes computed by the plugin. Even positive priorities can hide a
		// full-VPN root route; do not claim this is an effective snapshot.
		return result, fmt.Errorf("NetworkManager dnsmasq does not expose complete effective DNS routing metadata")
	}
	if mode != "default" {
		return result, fmt.Errorf("NetworkManager delegates DNS to an unavailable or unsupported provider")
	}
	for _, current := range candidates {
		selected := best[current.rule.Namespace]
		if current.global == selected.global && current.priority == selected.priority {
			result.Rules = append(result.Rules, current.rule)
		}
	}
	// In the file backend a negative priority excludes every other DNS
	// configuration. A root route prevents configured public fallback too.
	if mode == "default" && negative {
		var servers []net.IP
		for _, nameserver := range result.Nameservers {
			servers = appendDNSRouteIP(servers, nameserver.IP)
		}
		result.Rules = append(result.Rules, DNSRoutingRule{Namespace: ".", Servers: servers, Priority: DNSRouteLink})
	}
	rules, err := NormalizeDNSRoutingRules(result.Rules)
	result.Rules = rules
	return result, err
}
