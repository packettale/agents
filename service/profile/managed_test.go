package profile

import (
	"testing"

	"github.com/packettale/agents/base/config"
)

func TestManagedApplicationLayerOverridesLocalAndReleases(t *testing.T) { //nolint:paralleltest
	if _, err := config.GetOption(CfgOptionDefaultActionKey); err != nil {
		if err := config.Register(&config.Option{Name: "Default action test", Description: "Test action",
			Key: CfgOptionDefaultActionKey, OptType: config.OptTypeString,
			DefaultValue: DefaultActionPermitValue}); err != nil {
			t.Fatal(err)
		}
	}
	local := New(&Profile{ID: "managed-layer-test", Source: SourceLocal,
		Config: map[string]any{CfgOptionDefaultActionKey: DefaultActionPermitValue}})
	layered := NewLayeredProfile(local)
	local.layeredProfile = layered
	addActiveProfile(local)
	defer SetManagedApplicationRules(nil)
	if got := layered.DefaultAction(); got != DefaultActionPermit {
		t.Fatalf("local action=%d, want permit", got)
	}
	if err := SetManagedApplicationRules(map[string]map[string]any{
		local.ScopedID(): {CfgOptionDefaultActionKey: DefaultActionBlockValue},
	}); err != nil {
		t.Fatal(err)
	}
	if got := layered.DefaultAction(); got != DefaultActionBlock {
		t.Fatalf("managed action=%d, want block", got)
	}
	if layered.LocalProfile() != local {
		t.Fatal("management replaced local profile identity")
	}
	if err := SetManagedApplicationRules(map[string]map[string]any{
		local.ScopedID(): {"spn/use": true},
	}); err == nil {
		t.Fatal("unsupported application setting was accepted")
	}
	if got := layered.DefaultAction(); got != DefaultActionBlock {
		t.Fatalf("invalid replacement changed managed action: %d", got)
	}
	if err := SetManagedApplicationRules(nil); err != nil {
		t.Fatal(err)
	}
	if got := layered.DefaultAction(); got != DefaultActionPermit {
		t.Fatalf("released action=%d, want permit", got)
	}
}

func TestManagedGlobalLayerOverridesLocalAndAppException(t *testing.T) { //nolint:paralleltest
	if _, err := config.GetOption(CfgOptionDefaultActionKey); err != nil {
		if err := config.Register(&config.Option{Name: "Default action test", Description: "Test action",
			Key: CfgOptionDefaultActionKey, OptType: config.OptTypeString,
			DefaultValue: DefaultActionPermitValue}); err != nil {
			t.Fatal(err)
		}
	}
	local := New(&Profile{ID: "managed-global-test", Source: SourceLocal,
		Config: map[string]any{CfgOptionDefaultActionKey: DefaultActionPermitValue}})
	layered := NewLayeredProfile(local)
	local.layeredProfile = layered
	addActiveProfile(local)
	defer SetManagedProfileRules(nil, nil)

	if err := SetManagedProfileRules(map[string]any{CfgOptionDefaultActionKey: DefaultActionBlockValue}, nil); err != nil {
		t.Fatal(err)
	}
	if got := layered.DefaultAction(); got != DefaultActionBlock {
		t.Fatalf("managed global action=%d, want block", got)
	}
	if err := SetManagedProfileRules(map[string]any{CfgOptionDefaultActionKey: DefaultActionBlockValue},
		map[string]map[string]any{local.ScopedID(): {CfgOptionDefaultActionKey: DefaultActionPermitValue}}); err != nil {
		t.Fatal(err)
	}
	if got := layered.DefaultAction(); got != DefaultActionPermit {
		t.Fatalf("app exception action=%d, want permit", got)
	}
	if err := SetManagedProfileRules(nil, nil); err != nil {
		t.Fatal(err)
	}
	if got := layered.DefaultAction(); got != DefaultActionPermit {
		t.Fatalf("released action=%d, want local permit", got)
	}
}

func TestLocalFirewallAndSplitTunnelControlsRetainProfileIdentity(t *testing.T) {
	for _, option := range []*config.Option{
		{Name: "Default action", Description: "Test action", Key: CfgOptionDefaultActionKey, OptType: config.OptTypeString, DefaultValue: DefaultActionPermitValue},
		{Name: "Split tunnel", Description: "Test interface routing", Key: CfgOptionSplitTunUseKey, OptType: config.OptTypeBool, DefaultValue: false},
	} {
		if _, err := config.GetOption(option.Key); err != nil {
			if err := config.Register(option); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, enabled := range []bool{false, true} {
		local := New(&Profile{ID: "local-routing-controls", Source: SourceLocal, Config: config.Expand(map[string]any{CfgOptionDefaultActionKey: DefaultActionPermitValue, CfgOptionSplitTunUseKey: enabled})})
		layered := NewLayeredProfile(local)
		if layered.LocalProfile() != local || layered.DefaultAction() != DefaultActionPermit || layered.UseSplitTun() != enabled {
			t.Errorf("firewall, identity or interface routing changed (enabled=%v)", enabled)
		}
	}
}
