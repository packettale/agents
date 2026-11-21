package service

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/packettale/agents/base/api"
	"github.com/packettale/agents/base/config"
)

func TestManagementStopsBeforeItsConnectionStore(t *testing.T) {
	// Module constructors are process singletons. Keep this real-instance
	// check separate from the package's existing instance/debug tests.
	if os.Getenv("PACKETTALE_LIFECYCLE_FIXTURE") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestManagementStopsBeforeItsConnectionStore$", "-test.timeout=20s")
		cmd.Env = append(os.Environ(), "PACKETTALE_LIFECYCLE_FIXTURE=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("instance lifecycle fixture failed: %v: %s", err, output)
		}
		return
	}
	instance, err := New(&ServiceConfig{BinDir: t.TempDir(), DataDir: t.TempDir(), LogToStdout: true})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.cancelCtx()
	defer instance.cancelShutdownCtx()
	defer instance.netquery.Store.Close()
	storeIndex, managementIndex := -1, -1
	for index, module := range instance.serviceGroup.Modules() {
		if module == instance.netquery {
			storeIndex = index
		}
		if module == instance.management {
			managementIndex = index
		}
	}
	// The group starts forward and stops in reverse. Management performs
	// SQLite reads and writes until its workers finish; its store must outlive it.
	if storeIndex < 0 || managementIndex < 0 || managementIndex <= storeIndex {
		t.Fatalf("management lifetime does not fit inside its store lifetime: store=%d management=%d", storeIndex, managementIndex)
	}
}

func TestEndpointHasNoOperationalSPNModulesOrAPIs(t *testing.T) {
	if os.Getenv("PACKETTALE_SPN_REMOVAL_FIXTURE") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestEndpointHasNoOperationalSPNModulesOrAPIs$", "-test.timeout=20s")
		cmd.Env = append(os.Environ(), "PACKETTALE_SPN_REMOVAL_FIXTURE=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("SPN removal fixture failed: %v: %s", err, output)
		}
		return
	}
	instance, err := New(&ServiceConfig{BinDir: t.TempDir(), DataDir: t.TempDir(), LogToStdout: true})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.cancelCtx()
	defer instance.cancelShutdownCtx()
	defer instance.netquery.Store.Close()
	if instance.splittun == nil {
		t.Fatal("required split-tunnel module removed")
	}
	for _, key := range []string{"splittun/enable", "splittun/use", "splittun/networkInterface", "splittun/usagePolicy", "history/enable", "history/keep", "dns/followSystemRouting"} {
		if _, err := config.GetOption(key); err != nil {
			t.Errorf("required option removed: %s", key)
		}
	}
	for _, option := range config.ExportOptions() {
		if strings.HasPrefix(option.Key, "spn/") || strings.HasPrefix(option.Key, "filter/ask") || option.Key == "core/useSystemNotifications" {
			t.Errorf("excluded option registered: %s", option.Key)
		}
	}
	for _, endpoint := range api.ExportEndpoints() {
		if strings.HasPrefix(endpoint.Path, "spn/") || strings.HasPrefix(endpoint.Path, "account/") || strings.HasPrefix(endpoint.Path, "ui/") || strings.HasPrefix(endpoint.Path, "control/") || endpoint.Path == "enterprise/access-requests" {
			t.Errorf("Removed employee operation is still registered: %s", endpoint.Path)
		}
	}
}
