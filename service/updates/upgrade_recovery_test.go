package updates

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFailedUpgradeRestoresExecutableAndDirectoryPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix execution permissions")
	}
	u := recoveryTestUpdater(t)
	writeRecoveryTestFile(t, filepath.Join(u.cfg.Directory, "core"), "previous binary", 0o750)
	writeRecoveryTestFile(t, filepath.Join(u.cfg.Directory, "data"), "previous data", 0o640)
	directory := filepath.Join(u.cfg.Directory, "resources")
	t.Cleanup(func() { _ = os.Chmod(directory, 0o755) })
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	writeRecoveryTestFile(t, filepath.Join(directory, "asset"), "previous asset", 0o644)
	// The index was staged, but moving a missing artifact must trigger recovery.
	err := u.upgrade(&Downloader{index: &Index{Version: "1.0.1", Artifacts: []*Artifact{{Filename: "missing.bin"}}}}, true)
	if err == nil || !strings.Contains(err.Error(), "recovery was successful") {
		t.Fatalf("expected a recovered staging failure, got %v", err)
	}
	for name, expected := range map[string]os.FileMode{"core": 0o750, "resources": 0o700, "data": 0o640} {
		info, err := os.Stat(filepath.Join(u.cfg.Directory, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != expected {
			t.Errorf("restored %s permissions: got %v, want %v", name, info.Mode().Perm(), expected)
		}
	}
	if got, err := os.ReadFile(filepath.Join(directory, "asset")); err != nil || string(got) != "previous asset" {
		t.Fatalf("restored directory contents: %q, %v", got, err)
	}
}

func TestRecoveryReportsFailureAndContinuesRestoringOtherFiles(t *testing.T) {
	u := recoveryTestUpdater(t)
	writeRecoveryTestFile(t, filepath.Join(u.cfg.PurgeDirectory, "a-blocked"), "previous file", 0o644)
	if err := os.Mkdir(filepath.Join(u.cfg.Directory, "a-blocked"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeRecoveryTestFile(t, filepath.Join(u.cfg.Directory, "a-blocked", "occupied"), "collision", 0o644)
	writeRecoveryTestFile(t, filepath.Join(u.cfg.PurgeDirectory, "z-restorable"), "previous content", 0o644)
	if err := u.recoverFromFailedUpgrade(); err == nil || !strings.Contains(err.Error(), "a-blocked") {
		t.Errorf("failed restoration was reported as successful: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(u.cfg.Directory, "z-restorable")); err != nil || string(got) != "previous content" {
		t.Fatalf("recovery stopped before restoring another file: %q, %v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(u.cfg.PurgeDirectory, "a-blocked")); err != nil || string(got) != "previous file" {
		t.Fatalf("failed restoration did not retain the backup: %q, %v", got, err)
	}
}

func TestPostUpgradeFailureRestoresPreviousIndex(t *testing.T) {
	u := recoveryTestUpdater(t)
	previous := &Index{Version: "1.0.0"}
	u.index = previous
	u.cfg.PostUpgradeCommands = []UpdateCommandConfig{{Command: filepath.Join(t.TempDir(), "absent-command"), FailOnError: true}}
	err := u.upgrade(&Downloader{index: &Index{Version: "1.0.1"}}, true)
	if err == nil || !strings.Contains(err.Error(), "recovery was successful") {
		t.Fatalf("expected a recovered post-command failure, got %v", err)
	}
	if u.index != previous {
		t.Errorf("restored files have old index but updater still reports %s", u.index.Version)
	}
	if got, err := os.ReadFile(filepath.Join(u.cfg.Directory, "index.json")); err != nil || string(got) != "previous index" {
		t.Fatalf("previous index was not restored: %q, %v", got, err)
	}
}

func TestUpgradeBacksUpRelativeSymlinkAfterItsTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix installed symlink")
	}
	u := recoveryTestUpdater(t)
	writeRecoveryTestFile(t, filepath.Join(u.cfg.Directory, "a-core"), "previous binary", 0o755)
	if err := os.Symlink("a-core", filepath.Join(u.cfg.Directory, "z-link")); err != nil {
		t.Fatal(err)
	}
	writeRecoveryTestFile(t, filepath.Join(u.cfg.DownloadDirectory, "a-core"), "next binary", 0o755)
	next := &Index{Version: "1.0.1", Artifacts: []*Artifact{{Filename: "a-core", Platform: currentPlatform}}}
	if err := u.upgrade(&Downloader{index: next}, true); err != nil {
		t.Fatalf("moving the target first must not prevent backing up its symlink: %v", err)
	}
	if target, err := os.Readlink(filepath.Join(u.cfg.PurgeDirectory, "z-link")); err != nil || target != "a-core" {
		t.Fatalf("symlink was not backed up intact: %q, %v", target, err)
	}
	if got, err := os.ReadFile(filepath.Join(u.cfg.Directory, "a-core")); err != nil || string(got) != "next binary" {
		t.Fatalf("new artifact was not installed: %q, %v", got, err)
	}
}

func TestFailedUpgradeRemovesIntroducedArtifacts(t *testing.T) {
	u := recoveryTestUpdater(t)
	writeRecoveryTestFile(t, filepath.Join(u.cfg.Directory, "core"), "previous binary", 0o755)
	writeRecoveryTestFile(t, filepath.Join(u.cfg.DownloadDirectory, "new-artifact"), "new bytes", 0o644)
	next := &Index{Version: "1.0.1", Artifacts: []*Artifact{{Filename: "new-artifact"}, {Filename: "missing-artifact"}}}
	if err := u.upgrade(&Downloader{index: next}, true); err == nil {
		t.Fatal("expected the missing artifact to fail installation")
	}
	if _, err := os.Lstat(filepath.Join(u.cfg.Directory, "new-artifact")); !os.IsNotExist(err) {
		t.Errorf("failed update left a newly introduced artifact: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(u.cfg.Directory, "core")); err != nil || string(got) != "previous binary" {
		t.Fatalf("previous binary was not restored: %q, %v", got, err)
	}
}

func TestFailedUpgradeRemovesIndexIfPreviouslyAbsent(t *testing.T) {
	u := recoveryTestUpdater(t)
	if err := os.Remove(filepath.Join(u.cfg.Directory, "index.json")); err != nil {
		t.Fatal(err)
	}
	next := &Index{Version: "1.0.1", Artifacts: []*Artifact{{Filename: "missing-artifact"}}}
	if err := u.upgrade(&Downloader{index: next}, true); err == nil {
		t.Fatal("expected the missing artifact to fail installation")
	}
	if _, err := os.Lstat(filepath.Join(u.cfg.Directory, "index.json")); !os.IsNotExist(err) {
		t.Errorf("failed update left its index on a previously unindexed installation: %v", err)
	}
}

func TestBackupPreparationFailureLeavesInstallationUntouched(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires Unix directory permissions enforced for a non-root user")
	}
	u := recoveryTestUpdater(t)
	parent := t.TempDir()
	u.cfg.PurgeDirectory = filepath.Join(parent, "backup")
	if err := os.Mkdir(u.cfg.PurgeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
	assertBackupPreparationFailure(t, u)
}

func TestInvalidUpgradeTargetStopsBeforeMutation(t *testing.T) {
	for _, kind := range []string{"parent", "absolute", "directory"} {
		t.Run(kind, func(t *testing.T) {
			u := recoveryTestUpdater(t)
			outside := filepath.Join(filepath.Dir(u.cfg.Directory), "outside")
			writeRecoveryTestFile(t, outside, "unrelated file", 0o644)
			name := filepath.Join("..", "outside")
			if kind == "absolute" {
				name = outside
			} else if kind == "directory" {
				name = "."
			}
			err := u.upgrade(&Downloader{index: &Index{Artifacts: []*Artifact{{Filename: name}}}}, true)
			if err == nil || !strings.Contains(err.Error(), "invalid upgrade target") {
				t.Errorf("unsafe target reached installation: %v", err)
			}
			for _, test := range []struct{ path, want string }{
				{filepath.Join(u.cfg.Directory, "index.json"), "previous index"},
				{filepath.Join(u.cfg.DownloadDirectory, "index.json"), "next index"},
				{outside, "unrelated file"},
			} {
				if got, err := os.ReadFile(test.path); err != nil || string(got) != test.want {
					t.Errorf("rejected upgrade changed a file: %q, %v", got, err)
				}
			}
		})
	}
}

func TestFailedUpgradeRetainsUnexpectedDirectoryAndReportsRecoveryError(t *testing.T) {
	u := recoveryTestUpdater(t)
	writeRecoveryTestFile(t, filepath.Join(u.cfg.Directory, "core"), "previous binary", 0o755)
	staged := filepath.Join(u.cfg.DownloadDirectory, "unexpected-directory")
	if err := os.Mkdir(staged, 0o755); err != nil {
		t.Fatal(err)
	}
	writeRecoveryTestFile(t, filepath.Join(staged, "unrelated"), "retain these bytes", 0o644)
	u.cfg.PostUpgradeCommands = []UpdateCommandConfig{{Command: filepath.Join(t.TempDir(), "absent-command"), FailOnError: true}}
	next := &Index{Version: "1.0.1", Artifacts: []*Artifact{{Filename: "unexpected-directory", Platform: currentPlatform}}}
	err := u.upgrade(&Downloader{index: next}, true)
	if err == nil || !strings.Contains(err.Error(), "including recovery") || !strings.Contains(err.Error(), "remove introduced artifact unexpected-directory") || !strings.Contains(err.Error(), "post-upgrade command") {
		t.Errorf("cleanup failure must be returned with the original error: %v", err)
	}
	for _, test := range []struct{ name, want string }{
		{filepath.Join("unexpected-directory", "unrelated"), "retain these bytes"},
		{"core", "previous binary"},
	} {
		if got, err := os.ReadFile(filepath.Join(u.cfg.Directory, test.name)); err != nil || string(got) != test.want {
			t.Errorf("recovery lost retained or restored bytes: %q, %v", got, err)
		}
	}
}

func TestFailedUpgradeDoesNotRemoveUnattemptedArtifactBackup(t *testing.T) {
	u := recoveryTestUpdater(t)
	// Windows keeps its binary backup inside the installation directory.
	u.cfg.PurgeDirectory = filepath.Join(u.cfg.Directory, "upgrade_obsolete_binaries")
	writeRecoveryTestFile(t, filepath.Join(u.cfg.Directory, "core"), "previous binary", 0o755)
	next := &Index{Version: "1.0.1", Artifacts: []*Artifact{
		{Filename: "missing-artifact"},
		{Filename: filepath.Join("upgrade_obsolete_binaries", "core")},
	}}
	if err := u.upgrade(&Downloader{index: next}, true); err == nil {
		t.Fatal("expected the first artifact to fail installation")
	}
	if got, err := os.ReadFile(filepath.Join(u.cfg.Directory, "core")); err != nil || string(got) != "previous binary" {
		t.Fatalf("cleanup removed a backup for an artifact installation never reached: %q, %v", got, err)
	}
}

func assertBackupPreparationFailure(t *testing.T, u *Updater) {
	t.Helper()
	previous := &Index{Version: "1.0.0"}
	u.index = previous
	writeRecoveryTestFile(t, filepath.Join(u.cfg.Directory, "core"), "previous binary", 0o755)
	if err := u.upgrade(&Downloader{index: &Index{Version: "1.0.1"}}, true); err == nil {
		t.Error("update continued despite being unable to clear its backup directory")
	}
	if u.index != previous {
		t.Error("backup preparation failure changed the in-memory index")
	}
	for _, test := range []struct{ directory, name, want string }{
		{u.cfg.Directory, "index.json", "previous index"},
		{u.cfg.Directory, "core", "previous binary"},
		{u.cfg.DownloadDirectory, "index.json", "next index"},
	} {
		if got, err := os.ReadFile(filepath.Join(test.directory, test.name)); err != nil || string(got) != test.want {
			t.Errorf("backup preparation consumed or changed %s: %q, %v", test.name, got, err)
		}
	}
}

func recoveryTestUpdater(t *testing.T) *Updater {
	t.Helper()
	u := &Updater{cfg: Config{Directory: t.TempDir(), DownloadDirectory: t.TempDir(), PurgeDirectory: t.TempDir(), IndexFile: "index.json"}}
	writeRecoveryTestFile(t, filepath.Join(u.cfg.Directory, "index.json"), "previous index", 0o644)
	writeRecoveryTestFile(t, filepath.Join(u.cfg.DownloadDirectory, "index.json"), "next index", 0o644)
	return u
}

func writeRecoveryTestFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}
