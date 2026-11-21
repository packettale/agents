package service

import (
	"runtime"
	"slices"
	"testing"

	"github.com/packettale/agents/service/updates"
)

func TestEnterpriseUpdateConfigsKeepSoftwareFeedDisabled(t *testing.T) {
	cfg := &ServiceConfig{
		BinDir:            t.TempDir(),
		DataDir:           t.TempDir(),
		BinariesIndexURLs: []string{"https://updates.safing.io/stable.v3.json"},
		IntelIndexURLs:    []string{"https://updates.safing.io/intel.v3.json"},
	}

	binary, intel, err := MakeUpdateConfigs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if binary.AutoCheck || binary.AutoDownload || binary.AutoApply || len(binary.IndexURLs) != 0 {
		t.Fatalf("software updates must remain disabled in enterprise build: %+v", binary)
	}
	if !intel.AutoCheck || !intel.AutoDownload || !intel.AutoApply || len(intel.IndexURLs) == 0 {
		t.Fatalf("intelligence updates must remain enabled: %+v", intel)
	}
}

func TestManagedWindowsMaintenanceFilesSurviveSoftwareUpdates(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows updater ownership")
	}
	cfg := &ServiceConfig{BinDir: t.TempDir(), DataDir: t.TempDir()}
	binary, _, err := MakeUpdateConfigs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(binary.Ignore, "purge-data.ps1") {
		t.Fatal("signed update would delete the installed data-removal helper")
	}
}

func TestDefaultIntelUpdateConfigRejectsUnsignedIndexes(t *testing.T) {
	_, intel, err := MakeUpdateConfigs(&ServiceConfig{BinDir: t.TempDir(), DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if intel.Verify == nil {
		t.Fatal("intelligence signature verification must be enabled by default")
	}
	body := []byte(`{"Name":"Portmaster Intel","Version":"1.0.0","Published":"2026-11-17T00:00:00Z","Artifacts":[]}`)
	if _, err := updates.ParseIndex(body, "", intel.Verify); err == nil {
		t.Fatal("unsigned intelligence index was accepted")
	}
}
