package netenv

import (
	"context"
)

// Read the live providers instead of Nameservers, whose cache is invalidated by
// the network event this fingerprint is used to generate.
func systemDNSFingerprint(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	configuration, readErr := DNSConfiguration(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !FollowSystemDNSRouting() {
		configuration.Rules = nil
	}
	return systemDNSConfigurationFingerprint(configuration, nil, readErr), nil
}

// NetworkDNSSuffixes returns assigned scopes across active Linux providers.
func NetworkDNSSuffixes() []string {
	var suffixes []string
	for _, server := range Nameservers() {
		suffixes = append(suffixes, server.Search...)
	}
	return suffixes
}
