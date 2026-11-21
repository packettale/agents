package management

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	product "github.com/packettale/agents"
	"github.com/packettale/agents/base/info"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const windowsUninstallKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\packettale`

// Older self-updating installations keep their original registry view and
// uninstaller. Update only existing entries demonstrably owned by this binary.
func syncInstalledProductMetadata() error {
	version := info.VersionNumber()
	if version == "" || version == "0.0.0" {
		return nil
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	var failures []error
	for _, view := range []uint32{registry.WOW64_64KEY, registry.WOW64_32KEY} {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, windowsUninstallKey, registry.QUERY_VALUE|registry.SET_VALUE|view)
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			continue
		}
		if err != nil {
			failures = append(failures, err)
			continue
		}
		updateErr := syncWindowsInstallEntry(key, filepath.Dir(executable), version)
		closeErr := key.Close()
		failures = append(failures, updateErr, closeErr)
	}
	return errors.Join(failures...)
}

func syncWindowsInstallEntry(key registry.Key, binaryDir, version string) error {
	name, _, err := key.GetStringValue("DisplayName")
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return err
	}
	if name != "packettale" {
		return nil
	}
	command, _, err := key.GetStringValue("UninstallString")
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return err
	}
	args, err := windows.DecomposeCommandLine(command)
	if err != nil || len(args) != 1 || !filepath.IsAbs(args[0]) || !strings.EqualFold(filepath.Base(args[0]), "uninstall.exe") {
		return nil
	}
	// File identity handles directory aliases/junctions and avoids unsafe prefix
	// matching (e.g. another installation with a similar directory name).
	target, err := os.Stat(filepath.Dir(args[0]))
	if err != nil {
		return nil
	}
	current, err := os.Stat(binaryDir)
	if err != nil {
		return err
	}
	if !target.IsDir() || !current.IsDir() || !os.SameFile(target, current) {
		return nil
	}
	if err := ensureInstalledLegalNotice(binaryDir); err != nil {
		return err
	}
	previous, _, err := key.GetStringValue("DisplayVersion")
	if err == nil && previous == version {
		return nil
	}
	if err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return err
	}
	return key.SetStringValue("DisplayVersion", version)
}

func ensureInstalledLegalNotice(binaryDir string) (err error) {
	path := filepath.Join(binaryDir, "LICENSE.txt")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, os.ErrExist) {
		return nil
	} // Keep existing distribution notices.
	if err != nil {
		return fmt.Errorf("create installed legal notice: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.Remove(path)
		}
	}()
	text := product.LicenseText()
	n, writeErr := io.WriteString(file, text)
	if writeErr == nil && n != len(text) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	return errors.Join(writeErr, closeErr)
}
