package management

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	product "github.com/packettale/agents"

	"golang.org/x/sys/windows/registry"
)

func installEntryFixture(t *testing.T, binDir string) registry.Key {
	t.Helper()
	name := fmt.Sprintf(`Software\packettaleTests\InstallMetadata-%d`, time.Now().UnixNano())
	key, _, err := registry.CreateKey(registry.CURRENT_USER, name, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		key.Close()
		if err := registry.DeleteKey(registry.CURRENT_USER, name); err != nil {
			t.Error(err)
		}
	})
	for field, value := range map[string]string{"DisplayName": "packettale", "UninstallString": `"` + filepath.Join(binDir, "uninstall.exe") + `"`, "DisplayVersion": "2.2.5"} {
		if err := key.SetStringValue(field, value); err != nil {
			t.Fatal(err)
		}
	}
	return key
}

func TestWindowsOwnedInstallMetadataRepairsNoticeAndVersion(t *testing.T) {
	dir := t.TempDir()
	key := installEntryFixture(t, dir)
	if err := syncWindowsInstallEntry(key, dir, "2.2.16"); err != nil {
		t.Fatal(err)
	}
	version, _, err := key.GetStringValue("DisplayVersion")
	if err != nil || version != "2.2.16" {
		t.Fatalf("installed version=%q error=%v", version, err)
	}
	license, err := os.ReadFile(filepath.Join(dir, "LICENSE.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(license) != product.LicenseText() {
		t.Fatal("installed legal notice does not match the canonical distribution license")
	}
}

func TestWindowsInstallMetadataPreservesExistingNotices(t *testing.T) {
	dir := t.TempDir()
	key := installEntryFixture(t, dir)
	notice := []byte("existing distribution and third-party notices")
	if err := os.WriteFile(filepath.Join(dir, "LICENSE.txt"), notice, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := syncWindowsInstallEntry(key, dir, "2.2.16"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "LICENSE.txt"))
	if err != nil || string(got) != string(notice) {
		t.Fatalf("existing notice overwritten: %q error=%v", got, err)
	}
}

func TestWindowsInstallMetadataDoesNotClaimForeignEntries(t *testing.T) {
	for _, test := range []struct{ name, field, value string }{
		{"different directory", "UninstallString", `"` + filepath.Join(t.TempDir(), "uninstall.exe") + `"`},
		{"different product", "DisplayName", "Another application"},
		{"different executable", "UninstallString", `"` + filepath.Join(t.TempDir(), "other.exe") + `"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			key := installEntryFixture(t, dir)
			if err := key.SetStringValue(test.field, test.value); err != nil {
				t.Fatal(err)
			}
			if err := syncWindowsInstallEntry(key, dir, "2.2.16"); err != nil {
				t.Fatal(err)
			}
			if v, _, _ := key.GetStringValue("DisplayVersion"); v != "2.2.5" {
				t.Fatal("foreign install version changed")
			}
			if _, err := os.Stat(filepath.Join(dir, "LICENSE.txt")); !os.IsNotExist(err) {
				t.Fatal("foreign install legal file created")
			}
		})
	}
}
