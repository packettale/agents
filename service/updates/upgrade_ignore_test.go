package updates

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestUpgradeRetainsIgnoredInstalledFiles(t *testing.T) {
	for _, test := range []struct {
		name        string
		windowsOnly bool
	}{
		{"LICENSE.txt", false},
		{"license.txt", true},
		{"UnInStAlL.ExE", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			installed, download, purge := t.TempDir(), t.TempDir(), t.TempDir()
			notice := []byte("existing distribution-specific content")
			if err := os.WriteFile(filepath.Join(installed, test.name), notice, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(installed, "obsolete.bin"), []byte("old"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(download, "index.json"), []byte("{}"), 0o644); err != nil {
				t.Fatal(err)
			}
			updater := &Updater{cfg: Config{Directory: installed, DownloadDirectory: download, PurgeDirectory: purge, IndexFile: "index.json", Ignore: []string{"uninstall.exe", "LICENSE.txt"}}}
			if _, err := updater.upgradeMoveFiles(&Downloader{index: &Index{Version: "1.0.1"}}); err != nil {
				t.Fatal(err)
			}
			kept := !test.windowsOnly || runtime.GOOS == "windows"
			got, err := os.ReadFile(filepath.Join(installed, test.name))
			if kept {
				if err != nil || string(got) != string(notice) {
					t.Fatalf("installed ignored file was not preserved: content=%q error=%v", got, err)
				}
				if _, err := os.Stat(filepath.Join(purge, test.name)); !os.IsNotExist(err) {
					t.Fatalf("ignored file was moved to purge: %v", err)
				}
			} else if !os.IsNotExist(err) {
				t.Fatalf("case-sensitive filesystem retained a different filename: %v", err)
			}
			if _, err := os.Stat(filepath.Join(installed, "obsolete.bin")); !os.IsNotExist(err) {
				t.Fatalf("obsolete file was not removed: %v", err)
			}
			if got, err := os.ReadFile(filepath.Join(purge, "obsolete.bin")); err != nil || string(got) != "old" {
				t.Fatalf("obsolete file not available for rollback: %q %v", got, err)
			}
			if got, err := os.ReadFile(filepath.Join(installed, "index.json")); err != nil || string(got) != "{}" {
				t.Fatalf("update did not install the new index: %q %v", got, err)
			}
		})
	}
}
