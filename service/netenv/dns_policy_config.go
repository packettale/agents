package netenv

import "github.com/packettale/agents/base/config"

const CfgOptionFollowSystemRoutingKey = "dns/followSystemRouting"

// The resolver registers this control during its configuration preparation.
// NetEnv can also be used independently before that module is constructed.
// Reads occur only on configuration reload/monitor ticks, never per DNS packet.
func FollowSystemDNSRouting() bool {
	if _, err := config.GetOption(CfgOptionFollowSystemRoutingKey); err != nil {
		return true
	}
	return config.Concurrent.GetAsBool(CfgOptionFollowSystemRoutingKey, true)()
}
