//go:build !linux && !windows

package netenv

import "context"

func systemDNSFingerprint(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, nil
}
func NetworkDNSSuffixes() []string { return nil }

func DNSConfiguration(ctx context.Context) (SystemDNSConfiguration, error) {
	if err := ctx.Err(); err != nil {
		return SystemDNSConfiguration{}, err
	}
	return SystemDNSConfiguration{Nameservers: Nameservers()}, nil
}
