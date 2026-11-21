package netenv

import (
	"github.com/packettale/agents/service/network/netutils"
	"net/netip"
)

// KnownPublicAddresses returns only cached direct-interface or router-reported
// addresses. Traceroute hops and timezone estimates are not egress addresses.
// It performs no discovery traffic on the management reporting path.
func KnownPublicAddresses() map[string]string {
	locationsLock.Lock()
	defer locationsLock.Unlock()
	result := make(map[string]string)
	for _, location := range locations.All {
		if location.Source != SourceInterface && location.Source != SourceUPNP {
			continue
		}
		address, ok := netip.AddrFromSlice(location.IP)
		if !ok {
			continue
		}
		address = address.Unmap()
		if netutils.GetIPScope(location.IP) != netutils.Global || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
			continue
		}
		result[address.String()] = string(location.Source)
	}
	return result
}
