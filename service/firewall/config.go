package firewall

import (
	"github.com/tevino/abool"

	"github.com/packettale/agents/base/api"
	"github.com/packettale/agents/base/config"
	"github.com/packettale/agents/service/core"
)

// Configuration Keys.
var (
	CfgOptionEnableFilterKey = "filter/enable"
	filterEnabled            config.BoolOption

	CfgOptionPermanentVerdictsKey   = "filter/permanentVerdicts"
	cfgOptionPermanentVerdictsOrder = 80
	permanentVerdicts               config.BoolOption

	CfgOptionDNSQueryInterceptionKey   = "filter/dnsQueryInterception"
	cfgOptionDNSQueryInterceptionOrder = 81
	dnsQueryInterception               config.BoolOption
)

func registerConfig() error {
	err := config.Register(&config.Option{
		Name:           "Enable Privacy Filter",
		Key:            CfgOptionEnableFilterKey,
		Description:    "Enable network filtering. Turning this off disables network protection on this device.",
		OptType:        config.OptTypeBool,
		ExpertiseLevel: config.ExpertiseLevelDeveloper,
		ReleaseLevel:   config.ReleaseLevelExperimental,
		DefaultValue:   true,
		Annotations: config.Annotations{
			config.CategoryAnnotation: "General",
		},
	})
	if err != nil {
		return err
	}
	filterEnabled = config.Concurrent.GetAsBool(CfgOptionEnableFilterKey, true)

	err = config.Register(&config.Option{
		Name:           "Permanent Verdicts",
		Key:            CfgOptionPermanentVerdictsKey,
		Description:    "The firewall intercepts packets to decide whether to allow or deny connections. Usually the first packet is enough. Permanent verdicts avoid repeated inspection for that connection and improve performance.",
		OptType:        config.OptTypeBool,
		ExpertiseLevel: config.ExpertiseLevelDeveloper,
		ReleaseLevel:   config.ReleaseLevelExperimental,
		DefaultValue:   true,
		Annotations: config.Annotations{
			config.DisplayOrderAnnotation: cfgOptionPermanentVerdictsOrder,
			config.CategoryAnnotation:     "Advanced",
		},
	})
	if err != nil {
		return err
	}
	permanentVerdicts = config.Concurrent.GetAsBool(CfgOptionPermanentVerdictsKey, true)

	err = config.Register(&config.Option{
		Name:           "Seamless DNS Integration",
		Key:            CfgOptionDNSQueryInterceptionKey,
		Description:    "Intercept and redirect DNS queries to the firewall's internal DNS server. This enables DNS integration without manual system configuration, but may conflict with other software that intercepts DNS.",
		OptType:        config.OptTypeBool,
		ExpertiseLevel: config.ExpertiseLevelDeveloper,
		ReleaseLevel:   config.ReleaseLevelExperimental,
		DefaultValue:   true,
		Annotations: config.Annotations{
			config.DisplayOrderAnnotation: cfgOptionDNSQueryInterceptionOrder,
			config.CategoryAnnotation:     "Advanced",
		},
	})
	if err != nil {
		return err
	}
	dnsQueryInterception = config.Concurrent.GetAsBool(CfgOptionDNSQueryInterceptionKey, true)

	return nil
}

// Config variables for interception and filter module.
// Everything is registered by the interception module, as the filter module
// can be disabled.
var (
	devMode          config.BoolOption
	apiListenAddress config.StringOption

	configReady = abool.New()
)

func getConfig() {
	devMode = config.Concurrent.GetAsBool(core.CfgDevModeKey, false)
	apiListenAddress = config.GetAsString(api.CfgDefaultListenAddressKey, "")

	configReady.Set()
}
