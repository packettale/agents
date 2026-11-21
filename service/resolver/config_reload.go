package resolver

import (
	"strings"
	"sync"

	"github.com/packettale/agents/base/log"
	"github.com/packettale/agents/service/mgr"
	"github.com/packettale/agents/service/netenv"
)

// Keep configuration events serialized: the event manager may run callbacks
// concurrently when several managed settings change together.
func resolverConfigChangeCallback(reload func()) mgr.EventCallbackFunc[struct{}] {
	var lock sync.Mutex
	previous := strings.Join(configuredNameServers(), " ")
	previousRouting := netenv.FollowSystemDNSRouting()
	return func(_ *mgr.WorkerCtx, _ struct{}) (bool, error) {
		lock.Lock()
		defer lock.Unlock()
		current := strings.Join(configuredNameServers(), " ")
		currentRouting := netenv.FollowSystemDNSRouting()
		if current != previous || currentRouting != previousRouting {
			previous = current
			previousRouting = currentRouting
			reload()
			log.Debug("resolver: reloaded nameservers due to config change")
		}
		return false, nil
	}
}
