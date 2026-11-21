package firewall

import (
	"github.com/packettale/agents/service/network/packet"
	"testing"
)

func TestDNSRedirectionRequiresReadyMatchingSocket(t *testing.T) {
	previous := nameserverReadiness.Load()
	t.Cleanup(func() { nameserverReadiness.Store(previous) })
	nameserverReadiness.Store(nil)
	info := &packet.Info{Version: packet.IPv4, Protocol: packet.UDP}
	if nameserverReadyFor(info) {
		t.Fatal("DNS redirected before listener registration")
	}
	SetNameserverReadyMatcher(func(v packet.IPVersion, p packet.IPProtocol) bool { return v == packet.IPv4 && p == packet.UDP })
	if !nameserverReadyFor(info) {
		t.Fatal("ready listener ignored")
	}
	info.Protocol = packet.TCP
	if nameserverReadyFor(info) {
		t.Fatal("TCP redirected to unavailable listener")
	}
	SetNameserverReadyMatcher(func(packet.IPVersion, packet.IPProtocol) bool { return false })
	info.Protocol = packet.UDP
	if nameserverReadyFor(info) {
		t.Fatal("failed DNS listener retained redirection")
	}
}
