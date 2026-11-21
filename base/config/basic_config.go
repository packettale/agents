package config

import (
	"flag"

	"github.com/packettale/agents/base/log"
	"github.com/packettale/agents/service/mgr"
)

// Configuration Keys.
var (
	CfgDevModeKey                 = "core/devMode"
	defaultDevMode                bool
	CfgManagedEndpointReadOnlyKey = "core/management/readOnly"

	CfgLogLevel     = "core/log/level"
	defaultLogLevel = log.InfoLevel.String()
	logLevel        StringOption
)

func init() {
	flag.BoolVar(&defaultDevMode, "devmode", false, "allow unauthenticated local API access for diagnostics")
}

func registerBasicOptions() error {
	// Get the default log level from the log package.
	defaultLogLevel = log.GetLogLevel().Name()

	// Register logging setting.
	// The log package cannot do that, as it would trigger and import loop.
	if err := Register(&Option{
		Name:           "Log Level",
		Key:            CfgLogLevel,
		Description:    "Configure the logging level.",
		OptType:        OptTypeString,
		ExpertiseLevel: ExpertiseLevelDeveloper,
		ReleaseLevel:   ReleaseLevelStable,
		DefaultValue:   defaultLogLevel,
		Annotations: Annotations{
			DisplayOrderAnnotation: 513,
			DisplayHintAnnotation:  DisplayHintOneOf,
			CategoryAnnotation:     "Diagnostics",
		},
		PossibleValues: []PossibleValue{
			{
				Name:        "Critical",
				Value:       "critical",
				Description: "The critical level only logs errors that lead to a partial, but imminent failure.",
			},
			{
				Name:        "Error",
				Value:       "error",
				Description: "The error level logs errors that potentially break functionality. Everything logged by the critical level is included here too.",
			},
			{
				Name:        "Warning",
				Value:       "warning",
				Description: "The warning level logs minor errors and worse. Everything logged by the error level is included here too.",
			},
			{
				Name:        "Info",
				Value:       "info",
				Description: "The info level logs the main events that are going on and are interesting to the user. Everything logged by the warning level is included here too.",
			},
			{
				Name:        "Debug",
				Value:       "debug",
				Description: "The debug level logs some additional debugging details. Everything logged by the info level is included here too.",
			},
			{
				Name:        "Trace",
				Value:       "trace",
				Description: "The trace level logs loads of detailed information as well as operation and request traces. Everything logged by the debug level is included here too.",
			},
		},
	}); err != nil {
		return err
	}
	// Config change callbacks can run concurrently. Reuse the existing safe getter.
	logLevel = Concurrent.GetAsString(CfgLogLevel, defaultLogLevel)

	// Register to hook to update the log level.
	module.EventConfigChange.AddCallback("update log level", setLogLevel)

	if err := Register(&Option{
		Name:           "Unrestricted local API access",
		Key:            CfgDevModeKey,
		Description:    "Disable local API authentication for diagnostics. This reduces device security; enable only when directed by your administrator.",
		OptType:        OptTypeBool,
		ExpertiseLevel: ExpertiseLevelDeveloper,
		ReleaseLevel:   ReleaseLevelStable,
		DefaultValue:   defaultDevMode,
		Annotations: Annotations{
			DisplayOrderAnnotation: 512,
			CategoryAnnotation:     "Diagnostics",
		},
	}); err != nil {
		return err
	}

	return Register(&Option{
		Name:           "Enterprise Read-Only Status",
		Key:            CfgManagedEndpointReadOnlyKey,
		Description:    "Shows whether local policy changes are disabled by organization policy.",
		OptType:        OptTypeBool,
		ExpertiseLevel: ExpertiseLevelDeveloper,
		ReleaseLevel:   ReleaseLevelStable,
		DefaultValue:   false,
		Annotations: Annotations{
			DisplayOrderAnnotation: 514,
			CategoryAnnotation:     "Diagnostics",
		},
	})
}

func loadLogLevel() error {
	return setDefaultConfigOption(CfgLogLevel, log.GetLogLevel().Name(), false)
}

func setLogLevel(_ *mgr.WorkerCtx, _ struct{}) (cancel bool, err error) {
	log.SetLogLevel(log.ParseLevel(logLevel()))

	return false, nil
}
