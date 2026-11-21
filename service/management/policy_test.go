package management

import (
	"testing"

	"github.com/packettale/agents/base/config"
	"github.com/packettale/agents/service/profile"
)

func TestManagedDNSAndHistoryControls(t *testing.T) { //nolint:paralleltest
	for _, option := range []*config.Option{
		{Name: "DNS multicast", Description: "Test DNS option", Key: "dns/noMulticastDNS", OptType: config.OptTypeBool, DefaultValue: false},
		{Name: "History enabled", Description: "Test history option", Key: profile.CfgOptionEnableHistoryKey, OptType: config.OptTypeBool, DefaultValue: true},
		{Name: "History days", Description: "Test history retention", Key: profile.CfgOptionKeepHistoryKey, OptType: config.OptTypeInt, DefaultValue: 30},
	} {
		if _, err := config.GetOption(option.Key); err != nil {
			if err := config.Register(option); err != nil {
				t.Fatal(err)
			}
		}
	}
	defer config.SetManagedValue("dns/noMulticastDNS", nil)
	defer config.SetManagedValue(profile.CfgOptionEnableHistoryKey, nil)
	defer config.SetManagedValue(profile.CfgOptionKeepHistoryKey, nil)
	defer config.SetLocalWritesLocked(false)
	policy := Policy{Revision: 1, LocalHistoryDays: 90, GlobalSettings: map[string]any{
		"dns/noMulticastDNS": true, profile.CfgOptionEnableHistoryKey: false,
	}}
	if err := applyMandatoryPolicy(policy); err != nil {
		t.Fatal(err)
	}
	if err := syncManagedHistorySettings(policy); err != nil {
		t.Fatal(err)
	}
	if !config.GetAsBool("dns/noMulticastDNS", false)() ||
		config.GetAsBool(profile.CfgOptionEnableHistoryKey, true)() ||
		config.GetAsInt(profile.CfgOptionKeepHistoryKey, 30)() != 90 {
		t.Fatal("managed DNS or history controls did not reach endpoint configuration")
	}
	if err := applyMandatoryPolicy(Policy{Revision: 2, LocalHistoryDays: 30}); err != nil {
		t.Fatal(err)
	}
}

func TestGlobalSettingsPolicyValidationDoesNotReplaceActiveState(t *testing.T) { //nolint:paralleltest
	defer mandatoryDomains.Store(nil)
	defer mandatoryHistoryDays.Store(0)
	defer config.SetLocalWritesLocked(false)

	valid := Policy{Revision: 1, LocalHistoryDays: 90, MandatoryBlockDomains: []string{"example.com"}}
	if err := applyMandatoryPolicy(valid); err != nil {
		t.Fatal(err)
	}
	for _, settings := range []map[string]any{
		{"core/apiKeys": []string{"secret"}},
		{"spn/use": true},
		{"filter/blockInbound": "false"},
		{"filter/blockInbound": false, "core/devMode": true},
	} {
		invalid := Policy{Revision: 2, LocalHistoryDays: 30, LockLocalChanges: true,
			GlobalSettings: settings}
		if err := applyMandatoryPolicy(invalid); err == nil {
			t.Errorf("accepted settings %#v", settings)
		}
		if MandatoryHistoryDays() != 90 || !MandatoryBlockDomain("example.com") || !config.LocalWritesLocked() {
			t.Fatal("invalid global settings changed active policy")
		}
	}
}

func TestGlobalSettingOverridesGetterAndReleasesWhenRemoved(t *testing.T) { //nolint:paralleltest
	const key = "filter/blockInbound"
	if _, err := config.GetOption(key); err != nil {
		if err := config.Register(&config.Option{Name: "Managed inbound test", Description: "Test setting", Key: key,
			OptType: config.OptTypeBool, DefaultValue: false}); err != nil {
			t.Fatal(err)
		}
	}
	defer config.SetManagedValue(key, nil)
	defer mandatoryDomains.Store(nil)
	defer mandatoryHistoryDays.Store(0)

	getter := config.GetAsBool(key, false)
	if err := applyMandatoryPolicy(Policy{Revision: 1, LocalHistoryDays: 90,
		GlobalSettings: map[string]any{key: true}}); err != nil {
		t.Fatal(err)
	}
	if !getter() {
		t.Fatal("managed global setting did not reach cached getter")
	}
	if err := applyMandatoryPolicy(Policy{Revision: 2, LocalHistoryDays: 90}); err != nil {
		t.Fatal(err)
	}
	if getter() {
		t.Fatal("removed global setting did not restore local value")
	}
}

func TestManagedWriteLockCannotBeReleasedByPolicy(t *testing.T) { //nolint:paralleltest
	defer config.SetLocalWritesLocked(false)
	if err := applyMandatoryPolicy(Policy{Revision: 1, LocalHistoryDays: 90, LockLocalChanges: true}); err != nil {
		t.Fatal(err)
	}
	if !config.LocalWritesLocked() {
		t.Fatal("valid managed policy did not lock local writes")
	}
	if err := applyMandatoryPolicy(Policy{Revision: 2, LocalHistoryDays: 0, LockLocalChanges: false}); err == nil {
		t.Fatal("invalid policy accepted")
	}
	if !config.LocalWritesLocked() {
		t.Fatal("invalid policy released the active local write lock")
	}
	if err := applyMandatoryPolicy(Policy{Revision: 3, LocalHistoryDays: 90}); err != nil {
		t.Fatal(err)
	}
	if !config.LocalWritesLocked() {
		t.Fatal("managed policy released local write lock")
	}
}

func TestManagedPolicyRejectsPromptActions(t *testing.T) {
	for _, policy := range []Policy{
		{Revision: 1, LocalHistoryDays: 90, GlobalSettings: map[string]any{"filter/defaultAction": "ask"}},
		{Revision: 1, LocalHistoryDays: 90, ApplicationRules: map[string]map[string]any{
			"local/example": {"filter/defaultAction": "ask"},
		}},
	} {
		if _, err := validateMandatoryPolicy(policy); err == nil {
			t.Fatal("managed policy accepted a local prompt action")
		}
	}
}

func TestMandatoryDomainPolicy(t *testing.T) {
	defer mandatoryDomains.Store(nil)
	defer mandatoryHistoryDays.Store(0)
	if err := applyMandatoryPolicy(Policy{Revision: 1, LocalHistoryDays: 90,
		MandatoryBlockDomains: []string{"Example.COM", ".Office.Example"}}); err != nil {
		t.Fatal(err)
	}
	for domain, blocked := range map[string]bool{
		"example.com.":        true,
		"www.example.com.":    false,
		"office.example.":     true,
		"vpn.office.example.": true,
		"fakeoffice.example.": false,
		"other.example.":      false,
	} {
		if got := MandatoryBlockDomain(domain); got != blocked {
			t.Errorf("%q: blocked=%v, want %v", domain, got, blocked)
		}
	}
}

func TestInvalidMandatoryDomainsDoNotReplaceActivePolicy(t *testing.T) {
	defer mandatoryDomains.Store(nil)
	defer mandatoryHistoryDays.Store(0)
	if err := applyMandatoryPolicy(Policy{Revision: 1, LocalHistoryDays: 90,
		MandatoryBlockDomains: []string{"example.com"}}); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"*.example.com", "- example.com", "bad..example.com", "localhost"} {
		if err := applyMandatoryPolicy(Policy{Revision: 2, LocalHistoryDays: 30,
			MandatoryBlockDomains: []string{invalid}}); err == nil {
			t.Errorf("accepted invalid policy entry %q", invalid)
		}
	}
	if !MandatoryBlockDomain("example.com") || MandatoryHistoryDays() != 90 {
		t.Fatal("invalid policy replaced active mandatory settings")
	}
}

func TestManagedSystemDNSRoutingControl(t *testing.T) {
	const key = "dns/followSystemRouting"
	if _, err := config.GetOption(key); err != nil {
		if err := config.Register(&config.Option{Name: "System DNS routing", Description: "Test DNS routing control", Key: key, OptType: config.OptTypeBool, DefaultValue: true}); err != nil {
			t.Fatal(err)
		}
	}
	defer config.SetManagedValue(key, nil)
	defer config.SetLocalWritesLocked(false)
	defer mandatoryDomains.Store(nil)
	defer mandatoryHistoryDays.Store(0)
	if err := applyMandatoryPolicy(Policy{Revision: 1, LocalHistoryDays: 90, GlobalSettings: map[string]any{key: false}}); err != nil {
		t.Fatal("server cannot control OS DNS routing", err)
	}
	if config.GetAsBool(key, true)() {
		t.Fatal("managed DNS routing opt-out not applied")
	}
	if err := config.SetConfigOption(key, true); err == nil {
		t.Fatal("local change bypassed the managed DNS policy")
	}
	if err := applyMandatoryPolicy(Policy{Revision: 2, LocalHistoryDays: 90, GlobalSettings: map[string]any{key: "false"}}); err == nil {
		t.Fatal("invalid DNS routing control accepted")
	}
	if config.GetAsBool(key, true)() {
		t.Fatal("invalid policy changed active DNS routing control")
	}
}
