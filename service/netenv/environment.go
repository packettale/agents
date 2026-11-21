package netenv

import (
	"net"
	"sync/atomic"
	"time"

	"github.com/packettale/agents/service/mgr"
)

// TODO: find a good way to identify a network
// best options until now:
// MAC of gateway
// domain parameter of dhcp

// TODO: get dhcp servers on windows:
// doc: https://msdn.microsoft.com/en-us/library/windows/desktop/aa365917
// this info might already be included in the interfaces api provided by golang!

// Nameserver describes a system assigned namserver.
type Nameserver struct {
	IP     net.IP
	Search []string
	// ScopeOnly keeps routing-only link DNS out of unrelated global fallbacks.
	ScopeOnly bool
}

var nameserverDiscoveryRetry atomic.Bool

// RetryDNSDiscoveryAfter uses the existing network event so both the
// environment cache and resolver's active upstream list recover after a
// temporarily unavailable provider. Coalesce requests and stop with the module.
func RetryDNSDiscoveryAfter(delay time.Duration) {
	if module == nil || !nameserverDiscoveryRetry.CompareAndSwap(false, true) {
		return
	}
	module.m.Delay("retry DNS discovery", delay, func(_ *mgr.WorkerCtx) error {
		if nameserverDiscoveryRetry.CompareAndSwap(true, false) {
			notifyOfNetworkChange()
		}
		return nil
	})
}
