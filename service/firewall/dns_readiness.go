package firewall

import (
	"github.com/packettale/agents/base/log"
	"github.com/packettale/agents/service/firewall/interception"
	"github.com/packettale/agents/service/mgr"
	"github.com/packettale/agents/service/network"
	"github.com/packettale/agents/service/network/packet"
	"sync/atomic"
)

type nameserverReadyFunc func(packet.IPVersion, packet.IPProtocol) bool

var nameserverReadiness atomic.Pointer[nameserverReadyFunc]

// SetNameserverReadyMatcher supplies actual socket readiness for DNS redirection.
func SetNameserverReadyMatcher(match func(packet.IPVersion, packet.IPProtocol) bool) {
	fn := nameserverReadyFunc(match)
	nameserverReadiness.Store(&fn)
}

func nameserverReadyFor(info *packet.Info) bool {
	match := nameserverReadiness.Load()
	return match != nil && (*match)(info.Version, info.Protocol)
}

// dnsListenerUnavailable only relaxes DNS bypass prevention for actual outbound
// DNS connections whose matching listener is unavailable, not virtual DNS
// requests, other protocols or other firewall rules.
func dnsListenerUnavailable(conn *network.Connection) bool {
	if conn.Type != network.IPConnection || conn.Inbound || conn.Entity.Port != 53 {
		return false
	}
	if conn.IPVersion != packet.IPv4 && conn.IPVersion != packet.IPv6 {
		return false
	}
	if conn.IPProtocol != packet.UDP && conn.IPProtocol != packet.TCP {
		return false
	}
	return !nameserverReadyFor(&packet.Info{Version: conn.IPVersion, Protocol: conn.IPProtocol})
}

// RecheckDNSConnections refreshes cached UDP DNS decisions when a listener
// changes state. UDP clients can reuse their sockets across the transition.
func RecheckDNSConnections() {
	if module == nil {
		return
	}
	module.mgr.Go("refresh DNS listener decisions", func(w *mgr.WorkerCtx) error {
		for _, conn := range network.GetAllConnections() {
			conn.Lock()
			if conn.Type == network.IPConnection && !conn.Inbound && conn.IPProtocol == packet.UDP && conn.Entity != nil && conn.Entity.Port == 53 && conn.PID != ownPID && conn.DataIsComplete() {
				// Publish a complete decision to the OS. An undecided cached verdict can
				// drop packets if the connection's inspection worker has already stopped.
				conn.Internal = false
				conn.Inspecting = false
				conn.VerdictPermanent = false
				if dnsQueryInterception() && !module.instance.Resolver().IsDisabled() && nameserverReadyFor(&packet.Info{Version: conn.IPVersion, Protocol: conn.IPProtocol}) && nameserverIPMatcherReady.IsSet() && !nameserverIPMatcher(conn.Entity.IP) {
					conn.SetVerdict(network.VerdictRerouteToNameserver, "redirecting rogue dns query", "", nil)
					conn.Internal = true
					conn.StopFirewallHandler()
					info := packet.NewInfoPacket(packet.Info{Version: conn.IPVersion, Protocol: conn.IPProtocol, Src: conn.LocalIP, SrcPort: conn.LocalPort, Dst: conn.Entity.IP, DstPort: conn.Entity.Port, PID: conn.PID})
					info.SetCtx(w.Ctx())
					network.SaveDNSRequestConnection(conn, info)
				} else {
					conn.SetVerdictDirectly(network.VerdictUndecided)
					FilterConnection(w.Ctx(), conn, nil, true, true)
					conn.SetFirewallHandler(fastTrackHandler)
				}
				if err := interception.UpdateVerdictOfConnection(conn); err != nil {
					log.Tracer(w.Ctx()).Debugf("filter: could not refresh DNS socket decision: %s", err)
				}
				conn.Save()
			}
			conn.Unlock()
		}
		return nil
	})
}
