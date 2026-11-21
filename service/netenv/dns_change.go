package netenv

import (
	"crypto/sha256"
	"encoding/json"
	"slices"
)

// dnsConfigurationFingerprint includes the server/scope association, not merely
// a flattened domain list. Provider ordering has no meaning for change detection.
func dnsConfigurationFingerprint(servers []Nameserver, extra []string) []byte {
	entries := make([]string, 0, len(servers))
	for _, server := range servers {
		scopes := slices.Clone(server.Search)
		slices.Sort(scopes)
		data, _ := json.Marshal(struct {
			IP        string
			Scopes    []string
			ScopeOnly bool
		}{server.IP.String(), scopes, server.ScopeOnly})
		entries = append(entries, string(data))
	}
	slices.Sort(entries)
	other := slices.Clone(extra)
	slices.Sort(other)
	data, _ := json.Marshal([][]string{entries, other})
	sum := sha256.Sum256(data)
	return sum[:]
}

func systemDNSConfigurationFingerprint(configuration SystemDNSConfiguration, extra []string, readErr error) []byte {
	rules, _ := json.Marshal(configuration.Rules)
	metadata := append(append([]string(nil), extra...), string(rules))
	if readErr != nil {
		metadata = append(metadata, "system-dns-policy-unavailable")
	}
	return dnsConfigurationFingerprint(configuration.Nameservers, metadata)
}
