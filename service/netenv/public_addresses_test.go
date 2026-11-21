package netenv

import (
	"net"
	"testing"
)

func TestKnownPublicAddressesExcludesPrivateAndInferredLocations(t *testing.T) {
	locationsLock.Lock()
	original := locations
	locations = &DeviceLocations{All: []*DeviceLocation{
		{IP: net.ParseIP("8.8.8.8"), Source: SourceInterface},
		{IP: net.ParseIP("9.9.9.9"), Source: SourceUPNP},
		{IP: net.ParseIP("1.1.1.1"), Source: SourceTraceroute},
		{IP: net.ParseIP("10.1.0.1"), Source: SourceInterface},
		{IP: net.ParseIP("100.64.1.1"), Source: SourceInterface},
	}}
	locationsLock.Unlock()
	defer func() { locationsLock.Lock(); locations = original; locationsLock.Unlock() }()
	got := KnownPublicAddresses()
	if len(got) != 2 || got["8.8.8.8"] != "interface" || got["9.9.9.9"] != "upnp" {
		t.Fatalf("unverified public IP: %+v", got)
	}
}
