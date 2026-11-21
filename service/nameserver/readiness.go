package nameserver

import (
	"github.com/packettale/agents/service/firewall"
	"github.com/packettale/agents/service/network/packet"
	"net"
	"strings"
	"sync/atomic"
)

var readyListeners [2][2]atomic.Bool

func transportIndex(protocol packet.IPProtocol) int {
	switch protocol {
	case packet.UDP:
		return 0
	case packet.TCP:
		return 1
	default:
		return -1
	}
}

func setListenerReady(ip net.IP, transport string, ready bool) {
	protocol := packet.UDP
	if transport == "tcp" {
		protocol = packet.TCP
	}
	index := transportIndex(protocol)
	changed := false
	if ip.IsUnspecified() { // Go wildcard listeners accept both address families.
		if readyListeners[0][index].Swap(ready) != ready {
			changed = true
		}
		if readyListeners[1][index].Swap(ready) != ready {
			changed = true
		}
	} else if ip.To4() != nil {
		if readyListeners[0][index].Swap(ready) != ready {
			changed = true
		}
	} else {
		if readyListeners[1][index].Swap(ready) != ready {
			changed = true
		}
	}
	if changed && protocol == packet.UDP {
		firewall.RecheckDNSConnections()
	}
}

func listenerReady(version packet.IPVersion, protocol packet.IPProtocol) bool {
	index := transportIndex(protocol)
	if index < 0 {
		return false
	}
	switch version {
	case packet.IPv4:
		return readyListeners[0][index].Load()
	case packet.IPv6:
		return readyListeners[1][index].Load()
	default:
		return false
	}
}

// HealthState reports a failed listener even when another DNS service keeps
// name resolution available. Never imply DNS filtering works in that case.
func (ns *NameServer) HealthState() string {
	for _, state := range ns.states.Export().States {
		if strings.HasPrefix(state.ID, eventIDListenerFailed) || strings.HasPrefix(state.ID, eventIDConflictingService) {
			return "unavailable"
		}
	}
	if readyListeners[0][0].Load() && readyListeners[0][1].Load() {
		return "ready"
	}
	return "starting"
}
