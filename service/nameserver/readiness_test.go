package nameserver

import (
	"github.com/packettale/agents/service/network/packet"
	"net"
	"testing"
)

func TestDNSReadinessTracksListenerLifetimeAndTransport(t *testing.T) {
	for a := range readyListeners {
		for p := range readyListeners[a] {
			readyListeners[a][p].Store(false)
		}
	}
	t.Cleanup(func() {
		for a := range readyListeners {
			for p := range readyListeners[a] {
				readyListeners[a][p].Store(false)
			}
		}
	})
	ip := net.IPv4(127, 0, 0, 17)
	if listenerReady(packet.IPv4, packet.UDP) {
		t.Fatal("unbound listener advertised ready")
	}
	setListenerReady(ip, "udp", true)
	if !listenerReady(packet.IPv4, packet.UDP) || listenerReady(packet.IPv4, packet.TCP) || listenerReady(packet.IPv6, packet.UDP) {
		t.Fatal("readiness leaked across transports or address families")
	}
	setListenerReady(ip, "udp", false)
	if listenerReady(packet.IPv4, packet.UDP) {
		t.Fatal("failed/closed listener still receives redirected traffic")
	}
}
