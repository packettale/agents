package resolver

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/packettale/agents/base/config"
	"github.com/packettale/agents/service/netenv"
)

// Missing the routing switch in the configuration callback leaves the old
// private routes and their cache context published until a network event.
func TestConfigChangeReloadsSystemDNSRoutingImmediately(t *testing.T) {
	before := netenv.FollowSystemDNSRouting()
	t.Cleanup(func() { _ = config.SetConfigOption(netenv.CfgOptionFollowSystemRoutingKey, before) })
	var reloads atomic.Int32
	callback := resolverConfigChangeCallback(func() { reloads.Add(1) })
	for i, enabled := range []bool{!before, before} {
		if err := config.SetConfigOption(netenv.CfgOptionFollowSystemRoutingKey, enabled); err != nil {
			t.Fatal(err)
		}
		if _, err := callback(nil, struct{}{}); err != nil {
			t.Fatal(err)
		}
		if got := reloads.Load(); got != int32(i+1) {
			t.Fatalf("routing=%v: %d synchronous reloads, want %d", enabled, got, i+1)
		}
	}
	var workers sync.WaitGroup
	for range 10 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			_, _ = callback(nil, struct{}{})
		}()
	}
	workers.Wait()
	if reloads.Load() != 2 {
		t.Fatal("unchanged configuration caused additional reloads")
	}
}

func TestConfigChangeReloadsNameservers(t *testing.T) {
	before := append([]string(nil), configuredNameServers()...)
	t.Cleanup(func() { _ = config.SetConfigOption(CfgOptionNameServersKey, before) })
	var reloads int
	callback := resolverConfigChangeCallback(func() { reloads++ })
	if err := config.SetConfigOption(CfgOptionNameServersKey, []string{"dns://192.0.2.123"}); err != nil {
		t.Fatal(err)
	}
	_, _ = callback(nil, struct{}{})
	_, _ = callback(nil, struct{}{})
	if reloads != 1 {
		t.Fatalf("nameserver edit caused %d reloads, want 1", reloads)
	}
}
