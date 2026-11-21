package management

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

func ownedWindowsUninstall(install string) (string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, windowsUninstallKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", err
	}
	defer key.Close()
	name, _, err := key.GetStringValue("DisplayName")
	if err != nil || name != "packettale" {
		return "", errors.New("native packettale registration unavailable")
	}
	value, _, err := key.GetStringValue("UninstallString")
	if err != nil {
		return "", err
	}
	args, err := windows.DecomposeCommandLine(value)
	if err != nil || len(args) != 1 || !filepath.IsAbs(args[0]) || !strings.EqualFold(filepath.Base(args[0]), "uninstall.exe") {
		return "", errors.New("invalid native packettale uninstaller")
	}
	registered, err := os.Stat(filepath.Dir(args[0]))
	if err != nil {
		return "", err
	}
	directory, err := os.Stat(install)
	if err != nil {
		return "", err
	}
	if !os.SameFile(registered, directory) {
		return "", errors.New("uninstaller belongs to another installation")
	}
	return args[0], nil
}
func nativeInstallation(executable string) (string, error) {
	if !strings.EqualFold(filepath.Base(executable), "packettale-core.exe") {
		return "", errors.New("remote uninstall requires the installed service")
	}
	directory := filepath.Dir(executable)
	_, err := ownedWindowsUninstall(directory)
	return directory, err
}
func newUninstallDirectory() (string, error) {
	directory, err := os.MkdirTemp("", "packettale-uninstall-")
	if err != nil {
		return "", err
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err == nil {
		var dacl *windows.ACL
		dacl, _, err = descriptor.DACL()
		if err == nil {
			err = windows.SetNamedSecurityInfo(directory, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
		}
	}
	if err != nil {
		_ = os.Remove(directory)
		return "", err
	}
	return directory, nil
}
func prepareUninstallWorker(executable, directory string) (string, error) {
	worker := filepath.Join(directory, filepath.Base(executable))
	return worker, copyUninstallFile(executable, worker)
}
func validateUninstallExecutable(executable, directory string) error {
	if filepath.Dir(executable) != directory || !strings.EqualFold(filepath.Base(executable), "packettale-core.exe") {
		return errors.New("invalid uninstall worker executable")
	}
	return nil
}
func prepareNativeUninstaller(install, directory string) error {
	source, err := ownedWindowsUninstall(install)
	if err != nil {
		return err
	}
	return copyUninstallFile(source, filepath.Join(directory, "native-uninstall.exe"))
}
func startUninstallWorker(_ context.Context, worker, request, _ string) error {
	cmd := exec.Command(worker, "uninstall-worker", request)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_BREAKAWAY_FROM_JOB, HideWindow: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
func validateUninstallWorker(directory, request string) error {
	token := windows.GetCurrentProcessToken()
	if !token.IsElevated() {
		return errors.New("uninstall worker requires administrator privileges")
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("invalid uninstall directory")
	}
	ownerInfo, err := windows.GetNamedSecurityInfo(directory, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := ownerInfo.Owner()
	if err != nil {
		return err
	}
	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	if !owner.Equals(user.User.Sid) && !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return errors.New("uninstall directory ownership mismatch")
	}
	info, err = os.Lstat(request)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("invalid uninstall request")
	}
	return nil
}
func executeNativeUninstall(ctx context.Context, install, directory string, purge bool) (int, error) {
	if _, err := ownedWindowsUninstall(install); err != nil {
		return -1, err
	}
	executable := filepath.Join(directory, "native-uninstall.exe")
	commandLine := syscall.EscapeArg(executable) + " /S"
	if purge {
		commandLine += " /PURGE"
	}
	// NSIS requires _?= to be last and unquoted, even for paths with spaces.
	// CreateProcess executes this fixed binary directly; there is no command shell.
	commandLine += " _?=" + install
	cmd := exec.CommandContext(ctx, executable)
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: commandLine, HideWindow: true}
	err := cmd.Run()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode(), err
		}
		return -1, err
	}
	return 0, nil
}
func cleanupUninstallWorker(directory string) {
	_ = os.RemoveAll(directory)
	// Windows cannot unlink this mapped executable until it exits. Queue only
	// our private temporary worker and directory for deletion at the next boot.
	for _, path := range []string{filepath.Join(directory, "packettale-core.exe"), directory} {
		value, err := windows.UTF16PtrFromString(path)
		if err == nil {
			_ = windows.MoveFileEx(value, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
		}
	}
}
func nativeDataDirectory() (string, error) {
	root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	return filepath.Join(root, "packettale"), err
}
