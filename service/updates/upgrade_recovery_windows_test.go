package updates

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestLockedBackupLeavesInstallationUntouched(t *testing.T) {
	u := recoveryTestUpdater(t)
	path := filepath.Join(u.cfg.PurgeDirectory, "locked-backup")
	writeRecoveryTestFile(t, path, "previous backup", 0o644)
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	// Deny delete sharing so Windows cannot clear the previous backup.
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	assertBackupPreparationFailure(t, u)
}
