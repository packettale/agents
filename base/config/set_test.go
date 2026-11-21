//nolint:goconst
package config

import (
	"errors"
	"testing"
)

func TestManagedValuePreservesUserSettingAndRejectsWrites(t *testing.T) { //nolint:paralleltest
	options = make(map[string]*Option)
	configFilePath = ""
	quickRegister(t, "history/enable", OptTypeBool, false)
	if err := SetConfigOption("history/enable", false); err != nil {
		t.Fatal(err)
	}
	if err := SetManagedValue("history/enable", true); err != nil {
		t.Fatal(err)
	}
	if err := SetConfigOption("history/enable", false); !errors.Is(err, ErrManagedOption) {
		t.Fatalf("managed write: got %v", err)
	}
	if err := (&StorageInterface{}).Delete("history/enable"); !errors.Is(err, ErrManagedOption) {
		t.Fatalf("managed delete: got %v", err)
	}
	if errs, _ := ReplaceConfig(map[string]interface{}{"history/enable": true}); len(errs) != 1 || !errors.Is(errs[0], ErrManagedOption) {
		t.Fatalf("managed import: got %v", errs)
	}
	option, _ := GetOption("history/enable")
	if value := option.UserValue(); value != false {
		t.Fatalf("user value changed: %v", value)
	}
	if value, ok := option.GetAnnotation(ManagedValueAnnotation); !ok || value != true {
		t.Fatalf("managed annotation: %v, %v", value, ok)
	}
	if err := SetManagedValue("history/enable", nil); err != nil {
		t.Fatal(err)
	}
	if err := SetConfigOption("history/enable", true); err != nil {
		t.Fatalf("setting remained locked after release: %v", err)
	}
}

func TestManagedValueControlsEffectiveGetterAndReleasesToUserValue(t *testing.T) { //nolint:paralleltest
	options = make(map[string]*Option)
	configFilePath = ""
	quickRegister(t, "filter/blockInbound", OptTypeBool, true)
	if err := SetConfigOption("filter/blockInbound", true); err != nil {
		t.Fatal(err)
	}
	getValue := GetAsBool("filter/blockInbound", true)
	if !getValue() {
		t.Fatal("expected stored user value before policy")
	}
	if err := SetManagedValue("filter/blockInbound", false); err != nil {
		t.Fatal(err)
	}
	if getValue() {
		t.Fatal("managed value did not override cached effective getter")
	}
	if err := SetManagedValue("filter/blockInbound", nil); err != nil {
		t.Fatal(err)
	}
	if !getValue() {
		t.Fatal("releasing policy did not restore stored user value")
	}
}

func TestLocalWriteLockPublishesReadOnlyStatus(t *testing.T) { //nolint:paralleltest
	options = make(map[string]*Option)
	quickRegister(t, CfgManagedEndpointReadOnlyKey, OptTypeBool, false)
	status := GetAsBool(CfgManagedEndpointReadOnlyKey, false)
	SetLocalWritesLocked(true)
	if !status() {
		t.Fatal("read-only status did not follow local write lock")
	}
	SetLocalWritesLocked(false)
	if status() {
		t.Fatal("read-only status remained true after unlock")
	}
}

func TestLayersGetters(t *testing.T) { //nolint:paralleltest
	// reset
	options = make(map[string]*Option)

	mapData, err := JSONToMap([]byte(`
		{
			"monkey": "1",
			"elephant": 2,
			"zebras": {
				"zebra": ["black", "white"],
				"weird_zebra": ["black", -1]
			},
			"env": {
				"hot": true
			}
		}
    `))
	if err != nil {
		t.Fatal(err)
	}

	validationErrors, _ := ReplaceConfig(mapData)
	if len(validationErrors) > 0 {
		t.Fatalf("%d errors, first: %s", len(validationErrors), validationErrors[0].Error())
	}

	// Test missing values

	missingString := GetAsString("missing", "fallback")
	if missingString() != "fallback" {
		t.Error("expected fallback value: fallback")
	}

	missingStringArray := GetAsStringArray("missing", []string{"fallback"})
	if len(missingStringArray()) != 1 || missingStringArray()[0] != "fallback" {
		t.Error("expected fallback value: [fallback]")
	}

	missingInt := GetAsInt("missing", -1)
	if missingInt() != -1 {
		t.Error("expected fallback value: -1")
	}

	missingBool := GetAsBool("missing", false)
	if missingBool() {
		t.Error("expected fallback value: false")
	}

	// Test value mismatch

	notString := GetAsString("elephant", "fallback")
	if notString() != "fallback" {
		t.Error("expected fallback value: fallback")
	}

	notStringArray := GetAsStringArray("elephant", []string{"fallback"})
	if len(notStringArray()) != 1 || notStringArray()[0] != "fallback" {
		t.Error("expected fallback value: [fallback]")
	}

	mixedStringArray := GetAsStringArray("zebras/weird_zebra", []string{"fallback"})
	if len(mixedStringArray()) != 1 || mixedStringArray()[0] != "fallback" {
		t.Error("expected fallback value: [fallback]")
	}

	notInt := GetAsInt("monkey", -1)
	if notInt() != -1 {
		t.Error("expected fallback value: -1")
	}

	notBool := GetAsBool("monkey", false)
	if notBool() {
		t.Error("expected fallback value: false")
	}
}

func TestLayersSetters(t *testing.T) { //nolint:paralleltest
	// reset
	options = make(map[string]*Option)

	_ = Register(&Option{
		Name:            "name",
		Key:             "monkey",
		Description:     "description",
		ReleaseLevel:    ReleaseLevelStable,
		ExpertiseLevel:  ExpertiseLevelUser,
		OptType:         OptTypeString,
		DefaultValue:    "banana",
		ValidationRegex: "^(banana|water)$",
	})
	_ = Register(&Option{
		Name:            "name",
		Key:             "zebras/zebra",
		Description:     "description",
		ReleaseLevel:    ReleaseLevelStable,
		ExpertiseLevel:  ExpertiseLevelUser,
		OptType:         OptTypeStringArray,
		DefaultValue:    []string{"black", "white"},
		ValidationRegex: "^[a-z]+$",
	})
	_ = Register(&Option{
		Name:            "name",
		Key:             "elephant",
		Description:     "description",
		ReleaseLevel:    ReleaseLevelStable,
		ExpertiseLevel:  ExpertiseLevelUser,
		OptType:         OptTypeInt,
		DefaultValue:    2,
		ValidationRegex: "",
	})
	_ = Register(&Option{
		Name:            "name",
		Key:             "hot",
		Description:     "description",
		ReleaseLevel:    ReleaseLevelStable,
		ExpertiseLevel:  ExpertiseLevelUser,
		OptType:         OptTypeBool,
		DefaultValue:    true,
		ValidationRegex: "",
	})

	// correct types
	if err := SetConfigOption("monkey", "banana"); err != nil {
		t.Error(err)
	}
	if err := SetConfigOption("zebras/zebra", []string{"black", "white"}); err != nil {
		t.Error(err)
	}
	if err := SetDefaultConfigOption("elephant", 2); err != nil {
		t.Error(err)
	}
	if err := SetDefaultConfigOption("hot", true); err != nil {
		t.Error(err)
	}

	// incorrect types
	if err := SetConfigOption("monkey", []string{"black", "white"}); err == nil {
		t.Error("should fail")
	}
	if err := SetConfigOption("zebras/zebra", 2); err == nil {
		t.Error("should fail")
	}
	if err := SetDefaultConfigOption("elephant", true); err == nil {
		t.Error("should fail")
	}
	if err := SetDefaultConfigOption("hot", "banana"); err == nil {
		t.Error("should fail")
	}
	if err := SetDefaultConfigOption("hot", []byte{0}); err == nil {
		t.Error("should fail")
	}

	// validation fail
	if err := SetConfigOption("monkey", "dirt"); err == nil {
		t.Error("should fail")
	}
	if err := SetConfigOption("zebras/zebra", []string{"Element649"}); err == nil {
		t.Error("should fail")
	}

	// unregistered checking
	if err := SetConfigOption("invalid", "banana"); err == nil {
		t.Error("should fail")
	}
	if err := SetConfigOption("invalid", []string{"black", "white"}); err == nil {
		t.Error("should fail")
	}
	if err := SetConfigOption("invalid", 2); err == nil {
		t.Error("should fail")
	}
	if err := SetConfigOption("invalid", true); err == nil {
		t.Error("should fail")
	}
	if err := SetConfigOption("invalid", []byte{0}); err == nil {
		t.Error("should fail")
	}

	// delete
	if err := SetConfigOption("monkey", nil); err != nil {
		t.Error(err)
	}
	if err := SetDefaultConfigOption("elephant", nil); err != nil {
		t.Error(err)
	}
	if err := SetDefaultConfigOption("invalid_delete", nil); err == nil {
		t.Error("should fail")
	}
}
