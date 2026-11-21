package network

import (
	"net"
	"testing"

	"github.com/packettale/agents/service/network/packet"
)

func TestDNSRequestLookupSeparatesTCPAndUDP(t *testing.T) {
	tcp := &Connection{PID: 12001}
	udp := &Connection{PID: 12002}
	dnsRequestConnectionsLock.Lock()
	previous := dnsRequestConnections
	dnsRequestConnections = map[string]*Connection{
		"6-127.0.0.1-42005": tcp, "17-127.0.0.1-42005": udp,
		"6-::1-42005": tcp, "17-::1-42005": udp,
	}
	dnsRequestConnectionsLock.Unlock()
	t.Cleanup(func() {
		dnsRequestConnectionsLock.Lock()
		dnsRequestConnections = previous
		dnsRequestConnectionsLock.Unlock()
	})
	for _, ip := range []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback} {
		for _, test := range []struct {
			protocol packet.IPProtocol
			want     *Connection
		}{
			{packet.TCP, tcp}, {packet.UDP, udp},
		} {
			info := dnsRequestLookupInfo(ip, 42005, test.protocol)
			connection, ok := GetDNSRequestConnection(info)
			if !ok || connection != test.want {
				t.Fatalf("%s/%d selected wrong DNS process: %+v", ip, test.protocol, connection)
			}
		}
	}
}
