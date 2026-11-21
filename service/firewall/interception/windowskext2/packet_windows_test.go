package windowskext

import (
	"encoding/binary"
	"testing"

	"github.com/packettale/agents/service/network/packet"
	"github.com/miekg/dns"
)

func TestTransportOnlyDNSPayloadCanBeInspected(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeA)
	payload, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], 49152)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	pkt := &Packet{payload: udp, payloadLayer: 4}
	pkt.SetPacketInfo(packet.Info{Version: packet.IPv4, Protocol: packet.UDP})
	if err := pkt.LoadPacketData(); err != nil {
		t.Fatalf("transport-only DNS rejected: %v", err)
	}
	parsed := new(dns.Msg)
	if err := parsed.Unpack(pkt.Payload()); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Question) != 1 || parsed.Question[0].Name != "example.test." {
		t.Fatalf("incorrect DNS payload: %v", parsed.Question)
	}
	if err := pkt.LoadPacketData(); err != nil {
		t.Fatalf("second payload read failed: %v", err)
	}
}
