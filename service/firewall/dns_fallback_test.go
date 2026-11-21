package firewall

import (
	"context"
	"testing"

	"github.com/packettale/agents/service/network"
	"github.com/packettale/agents/service/network/packet"
)

type blockedDNSPacket struct {
	packet.Packet
	blocked, accepted, payloadLoaded bool
}

func (*blockedDNSPacket) InfoOnly() bool                 { return false }
func (*blockedDNSPacket) FastTrackedByIntegration() bool { return false }
func (*blockedDNSPacket) Ctx() context.Context           { return context.Background() }
func (p *blockedDNSPacket) Block() error                 { p.blocked = true; return nil }
func (p *blockedDNSPacket) Accept() error                { p.accepted = true; return nil }
func (p *blockedDNSPacket) LoadPacketData() error        { p.payloadLoaded = true; return nil }

func TestDNSObservationCannotOverrideFirewallBlock(t *testing.T) {
	previous := permanentVerdicts
	permanentVerdicts = func() bool { return false }
	t.Cleanup(func() { permanentVerdicts = previous })
	conn := &network.Connection{Verdict: network.VerdictBlock, Inspecting: true}
	pkt := &blockedDNSPacket{}
	inspectDNSPacket(conn, pkt)
	if !pkt.blocked || pkt.accepted || pkt.payloadLoaded {
		t.Fatalf("blocked DNS entered observation: blocked=%v accepted=%v loaded=%v", pkt.blocked, pkt.accepted, pkt.payloadLoaded)
	}
}
