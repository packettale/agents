package profile

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/packettale/agents/base/config"
)

var managedApplicationLayers atomic.Pointer[map[string]*Profile]
var managedGlobalLayer atomic.Pointer[Profile]
var managedGlobalSettings atomic.Pointer[map[string]any]

var allowedManagedApplicationSettings = map[string]struct{}{
	CfgOptionSplitTunUseKey:         {},
	CfgOptionSplitTunInterfaceKey:   {},
	CfgOptionSplitTunUsagePolicyKey: {},
	CfgOptionDefaultActionKey:       {},
	CfgOptionBlockScopeInternetKey:  {},
	CfgOptionBlockScopeLANKey:       {},
	CfgOptionBlockScopeLocalKey:     {},
	CfgOptionBlockP2PKey:            {},
	CfgOptionBlockInboundKey:        {},
	CfgOptionEndpointsKey:           {},
	CfgOptionServiceEndpointsKey:    {},
	CfgOptionFilterListsKey:         {},
	CfgOptionFilterSubDomainsKey:    {},
	CfgOptionFilterCNAMEKey:         {},
	CfgOptionRemoveOutOfScopeDNSKey: {},
	CfgOptionRemoveBlockedDNSKey:    {},
	CfgOptionDomainHeuristicsKey:    {},
	CfgOptionPreventBypassingKey:    {},
	CfgOptionDisableAutoPermitKey:   {},
	CfgOptionEnableHistoryKey:       {},
	CfgOptionKeepHistoryKey:         {},
}

// SetManagedApplicationRules replaces the in-memory managed profile layer.
// Local profile records and their history remain untouched.
func ValidateManagedApplicationRules(rules map[string]map[string]any) error {
	_, err := prepareManagedApplicationRules(rules)
	return err
}

func prepareManagedApplicationRules(rules map[string]map[string]any) (map[string]*Profile, error) {
	if len(rules) > 500 {
		return nil, fmt.Errorf("too many managed application profiles")
	}
	prepared := make(map[string]*Profile, len(rules))
	for scopedID, settings := range rules {
		id, ok := strings.CutPrefix(scopedID, "local/")
		if !ok || id == "" || len(id) > 200 || strings.ContainsAny(id, "/\\") {
			return nil, fmt.Errorf("invalid managed application profile ID %q", scopedID)
		}
		if len(settings) == 0 || len(settings) > len(allowedManagedApplicationSettings) {
			return nil, fmt.Errorf("invalid managed application settings for %q", scopedID)
		}
		for key, value := range settings {
			if _, ok := allowedManagedApplicationSettings[key]; !ok {
				return nil, fmt.Errorf("unsupported managed application setting %q", key)
			}
			if err := config.ValidateManagedValue(key, value); err != nil {
				return nil, fmt.Errorf("invalid managed application setting %q: %w", key, err)
			}
		}
		layer := &Profile{ID: "enterprise-" + id, Source: SourceSpecial,
			Name: "Organization Policy", Config: config.Expand(settings), Internal: true}
		layer.makeKey()
		layer.prepProfile()
		if err := layer.parseConfig(); err != nil {
			return nil, fmt.Errorf("invalid managed application profile %q: %w", scopedID, err)
		}
		prepared[scopedID] = layer
	}
	return prepared, nil
}

func SetManagedApplicationRules(rules map[string]map[string]any) error {
	var global map[string]any
	if current := managedGlobalSettings.Load(); current != nil {
		global = *current
	}
	return SetManagedProfileRules(global, rules)
}

// ValidateManagedProfileRules validates both layers without changing any
// active profile.
func ValidateManagedProfileRules(global map[string]any, apps map[string]map[string]any) error {
	if _, err := prepareManagedGlobalLayer(global); err != nil {
		return err
	}
	_, err := prepareManagedApplicationRules(apps)
	return err
}

// SetManagedProfileRules installs app-specific rules ahead of managed global
// rules, with local application settings as the final fallback.
func SetManagedProfileRules(global map[string]any, rules map[string]map[string]any) error {
	globalLayer, err := prepareManagedGlobalLayer(global)
	if err != nil {
		return err
	}
	prepared, err := prepareManagedApplicationRules(rules)
	if err != nil {
		return err
	}

	getProfileLock.Lock()
	managedGlobalLayer.Store(globalLayer)
	managedGlobalSettings.Store(&global)
	managedApplicationLayers.Store(&prepared)
	changed := make([]string, 0)
	for _, local := range getAllActiveProfiles() {
		if local.layeredProfile != nil {
			local.layeredProfile.setManagedLayers(prepared[local.ScopedID()], globalLayer)
			changed = append(changed, local.ScopedID())
		}
	}
	getProfileLock.Unlock()
	if module != nil {
		for _, scopedID := range changed {
			module.EventConfigChange.Submit(scopedID)
		}
	}
	return nil
}

func prepareManagedGlobalLayer(settings map[string]any) (*Profile, error) {
	profileSettings := make(map[string]any)
	for key, value := range settings {
		if _, ok := allowedManagedApplicationSettings[key]; !ok {
			continue // Global-only options do not have a per-application layer.
		}
		if err := config.ValidateManagedValue(key, value); err != nil {
			return nil, err
		}
		profileSettings[key] = value
	}
	if len(profileSettings) == 0 {
		return nil, nil
	}
	layer := &Profile{ID: "enterprise-global", Source: SourceSpecial,
		Name: "Organization Global Policy", Config: config.Expand(profileSettings), Internal: true}
	layer.makeKey()
	layer.prepProfile()
	if err := layer.parseConfig(); err != nil {
		return nil, err
	}
	return layer, nil
}

func managedLayerFor(scopedID string) *Profile {
	if layers := managedApplicationLayers.Load(); layers != nil {
		return (*layers)[scopedID]
	}
	return nil
}

func managedGlobalLayerFor() *Profile { return managedGlobalLayer.Load() }
