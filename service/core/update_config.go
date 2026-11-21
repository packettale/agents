package core

import (
	"github.com/packettale/agents/base/config"
	"github.com/packettale/agents/service/configure"
	"github.com/packettale/agents/service/mgr"
)

// Release Channel Configuration Keys.
const (
	ReleaseChannelKey     = "core/releaseChannel"
	ReleaseChannelJSONKey = "core.releaseChannel"
)

// Release Channels.
const (
	ReleaseChannelStable  = "stable"
	ReleaseChannelBeta    = "beta"
	ReleaseChannelStaging = "staging"
	ReleaseChannelSupport = "support"
)

const (
	enableSoftwareUpdatesKey = "core/automaticUpdates"
	enableIntelUpdatesKey    = "core/automaticIntelUpdates"
)

var (
	releaseChannel     config.StringOption
	enableIntelUpdates config.BoolOption

	initialReleaseChannel string
)

func registerUpdateConfig() error {
	err := config.Register(&config.Option{
		Name:            "Release Channel",
		Key:             ReleaseChannelKey,
		Description:     `Use "Stable" for the best experience. The "Beta" channel will have the newest features and fixes, but may also break and cause interruption. Use others only temporarily and when instructed.`,
		OptType:         config.OptTypeString,
		ExpertiseLevel:  config.ExpertiseLevelExpert,
		ReleaseLevel:    config.ReleaseLevelStable,
		RequiresRestart: true,
		DefaultValue:    ReleaseChannelStable,
		PossibleValues: []config.PossibleValue{
			{
				Name:        "Stable",
				Description: "Recommended releases.",
				Value:       ReleaseChannelStable,
			},
			{
				Name:        "Beta",
				Description: "Preview releases. Features may change and service interruptions can occur.",
				Value:       ReleaseChannelBeta,
			},
			{
				Name:        "Support",
				Description: "Support releases or version changes for troubleshooting. Only use temporarily and when instructed.",
				Value:       ReleaseChannelSupport,
			},
			{
				Name:        "Preview",
				Description: "Early preview releases. Use only when directed by support; service interruptions can occur.",
				Value:       ReleaseChannelStaging,
			},
		},
		Annotations: config.Annotations{
			config.DisplayOrderAnnotation: -4,
			config.DisplayHintAnnotation:  config.DisplayHintOneOf,
			config.CategoryAnnotation:     "Updates",
		},
	})
	if err != nil {
		return err
	}

	err = config.Register(&config.Option{
		Name:            "Automatic Software Updates",
		Key:             enableSoftwareUpdatesKey,
		Description:     "Your organisation manages software updates from the PacketTale portal.",
		OptType:         config.OptTypeBool,
		ExpertiseLevel:  config.ExpertiseLevelExpert,
		ReleaseLevel:    config.ReleaseLevelStable,
		RequiresRestart: false,
		DefaultValue:    false,
		Annotations: config.Annotations{
			config.DisplayOrderAnnotation: -12,
			config.CategoryAnnotation:     "Updates",
		},
	})
	if err != nil {
		return err
	}

	err = config.Register(&config.Option{
		Name:            "Automatic Intelligence Data Updates",
		Key:             enableIntelUpdatesKey,
		Description:     "Automatically check for and download intelligence data updates. This includes filter lists, geo-ip data, and more. Does not include software updates.",
		OptType:         config.OptTypeBool,
		ExpertiseLevel:  config.ExpertiseLevelExpert,
		ReleaseLevel:    config.ReleaseLevelStable,
		RequiresRestart: false,
		DefaultValue:    true,
		Annotations: config.Annotations{
			config.DisplayOrderAnnotation: -11,
			config.CategoryAnnotation:     "Updates",
		},
	})
	if err != nil {
		return err
	}

	return nil
}

func initUpdateConfig() {
	releaseChannel = config.Concurrent.GetAsString(ReleaseChannelKey, ReleaseChannelStable)
	enableIntelUpdates = config.Concurrent.GetAsBool(enableIntelUpdatesKey, true)

	initialReleaseChannel = releaseChannel()

	module.instance.Config().EventConfigChange.AddCallback("configure updates", func(wc *mgr.WorkerCtx, s struct{}) (cancel bool, err error) {
		configureUpdates()
		return false, nil
	})
	configureUpdates()
}

func configureUpdates() {
	// The upstream binary feed cannot upgrade an enterprise-managed endpoint.
	// Keep the intelligence feed active so filter lists and geo-IP data stay current.
	module.instance.BinaryUpdates().Configure(false, nil)
	module.instance.IntelUpdates().Configure(enableIntelUpdates(), configure.DefaultIntelIndexURLs)
}
