package resolver

import (
	"github.com/packettale/agents/base/config"
	"testing"
)

func TestSystemDNSRoutingConfigRegistered(t *testing.T) {
	option, err := config.GetOption("dns/followSystemRouting")
	if err != nil {
		t.Fatal("system DNS routing control missing from endpoint options", err)
	}
	if option.OptType != config.OptTypeBool || option.DefaultValue != true {
		t.Fatal("system DNS routing must be a boolean enabled by default")
	}
}
