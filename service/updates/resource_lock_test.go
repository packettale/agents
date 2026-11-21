package updates

import (
	"github.com/tevino/abool"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUpgradeWaitsForResourceReader(t *testing.T) {
	u := recoveryTestUpdater(t)
	path := filepath.Join(u.cfg.Directory, "base.dsdl")
	writeRecoveryTestFile(t, path, "previous feed", 0600)
	writeRecoveryTestFile(t, filepath.Join(u.cfg.DownloadDirectory, "base.dsdl"), "next feed", 0600)
	entered, release, readDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		readDone <- u.ReadResources(func() error {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer f.Close()
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	upgraded := make(chan error, 1)
	go func() {
		upgraded <- u.upgrade(&Downloader{index: &Index{Version: "1.0.1", Artifacts: []*Artifact{{Filename: "base.dsdl"}}}}, true)
	}()
	select {
	case err := <-upgraded:
		close(release)
		<-readDone
		t.Fatalf("upgrade passed an active file reader: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "previous feed" {
		t.Errorf("active feed changed: %q %v", got, err)
	}
	close(release)
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-upgraded:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upgrade did not resume after file closed")
	}
	got, err = os.ReadFile(path)
	if err != nil || string(got) != "next feed" {
		t.Fatalf("new feed not installed: %q %v", got, err)
	}
}

func TestUpdateStateDistinguishesActivityAndFailure(t *testing.T) {
	u := recoveryTestUpdater(t)
	u.isUpdateRunning = abool.New()
	if u.UpdateState() != "idle" {
		t.Fatal("new updater is not idle")
	}
	u.lastUpdateFailed.Store(true)
	if u.UpdateState() != "failed" {
		t.Fatal("failure hidden")
	}
	u.isUpdateRunning.Set()
	if u.UpdateState() != "updating" {
		t.Fatal("active retry hidden")
	}
}
